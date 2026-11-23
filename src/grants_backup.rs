use super::Store;
use base64::Engine;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PREFIX: &str = "gateway-backup-v1-";
const MANIFEST_LIMIT: u64 = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("authority backup I/O failed")]
    Io(#[from] std::io::Error),
    #[error("authority backup database unavailable")]
    Database(#[from] rusqlite::Error),
    #[error("authority backup source is invalid")]
    Store(#[from] super::Error),
    #[error("authority backup migration inspection failed")]
    Inspection(#[from] crate::outbound::Error),
    #[error("authority backup directory must be private and owned by the store UID")]
    Directory,
    #[error("authority backup publication refused")]
    Publication,
    #[error("authority backup remained busy")]
    Busy,
    #[error("authority backup directory locking unavailable")]
    Coordination(#[source] std::io::Error),
    #[error("authority backup metadata unavailable")]
    Metadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupResult {
    NoPendingMigrations,
    Published,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    store: String,
    created_ns: u64,
    nonce: String,
    database_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn name(manifest: &Manifest) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&manifest.store)
        .ok()?;
    if base64::engine::general_purpose::STANDARD.encode(&bytes) != manifest.store {
        return None;
    }
    Some(format!(
        "{PREFIX}{}-{:016x}-{}",
        hex(&Sha256::digest(&bytes)),
        manifest.created_ns,
        manifest.nonce
    ))
}

fn hex_field(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_file(path: &Path, owner: &Metadata) -> Result<File, BackupError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(BackupError::Metadata);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != owner.uid() || metadata.mode() & 0o777 != 0o600 {
            return Err(BackupError::Metadata);
        }
    }
    Ok(file)
}
fn digest_file(path: &Path, owner: &Metadata) -> Result<String, BackupError> {
    let mut file = private_file(path, owner)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex(&hash.finalize()))
}
fn create_private_file(path: &Path) -> Result<File, BackupError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn create_directory(path: &Path) -> Result<(), BackupError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
fn validate_directory(path: &Path, owner: &Metadata) -> Result<Metadata, BackupError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(BackupError::Directory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != owner.uid() || metadata.mode() & 0o777 != 0o700 {
            return Err(BackupError::Directory);
        }
    }
    Ok(metadata)
}
fn same_directory(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.created()
            .ok()
            .zip(right.created().ok())
            .is_some_and(|(a, b)| a == b)
    }
}
fn ensure_root(path: &Path, owner: &Metadata) -> Result<(), BackupError> {
    match create_directory(path) {
        Ok(()) => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        Err(BackupError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_directory(path, owner)?;
    Ok(())
}
fn lock_directory(root: &Path, owner: &Metadata, wait: Duration) -> Result<File, BackupError> {
    lock_directory_with(root, owner, wait, File::try_lock)
}
fn lock_directory_with(
    root: &Path,
    owner: &Metadata,
    wait: Duration,
    attempt: fn(&File) -> Result<(), std::fs::TryLockError>,
) -> Result<File, BackupError> {
    let expected = validate_directory(root, owner)?;
    let handle = File::open(root)?;
    if !same_directory(&expected, &handle.metadata()?) {
        return Err(BackupError::Directory);
    }
    let started = Instant::now();
    loop {
        match attempt(&handle) {
            Ok(()) => return Ok(handle),
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= wait {
                    return Err(BackupError::Busy);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(BackupError::Coordination(error))
            }
        }
    }
}
fn snapshot(connection: &Connection, target: &Path) -> Result<(), BackupError> {
    drop(create_private_file(target)?);
    let mut destination = Connection::open_with_flags(target, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    destination.busy_timeout(Duration::ZERO)?;
    destination.pragma_update(None, "synchronous", "FULL")?;
    {
        let backup = Backup::new(connection, &mut destination)?;
        let mut busy_since = None;
        loop {
            let step_started = Instant::now();
            match backup.step(64)? {
                StepResult::Done => break,
                StepResult::More => busy_since = None,
                StepResult::Busy | StepResult::Locked => {
                    if busy_since.get_or_insert(step_started).elapsed() >= Duration::from_secs(30) {
                        return Err(BackupError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => return Err(BackupError::Metadata),
            }
        }
    }
    // Published snapshots do not depend on destination WAL sidecars.
    destination.pragma_update(None, "journal_mode", "DELETE")?;
    let integrity: Vec<String> = destination
        .prepare("PRAGMA quick_check")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if integrity != ["ok"] {
        return Err(BackupError::Metadata);
    }
    Store::validate_connection(&destination)?;
    destination
        .close()
        .map_err(|(_, error)| BackupError::Database(error))?;
    File::open(target)?.sync_all()?;
    Ok(())
}
fn publish(
    pending: &Path,
    completed: &Path,
    reservation: &File,
    owner: &Metadata,
    directory_lock: &File,
) -> Result<(), BackupError> {
    let current = validate_directory(completed, owner)?;
    if !same_directory(&current, &reservation.metadata()?)
        || fs::read_dir(completed)?.next().is_some()
    {
        return Err(BackupError::Publication);
    }
    fs::rename(pending, completed)?;
    directory_lock.sync_all()?;
    Ok(())
}
struct Completed {
    path: PathBuf,
    created_ns: u64,
    nonce: String,
}
fn completed(path: &Path, store: &str, owner: &Metadata) -> Option<Completed> {
    validate_directory(path, owner).ok()?;
    let mut encoded = Vec::new();
    private_file(&path.join("manifest.json"), owner)
        .ok()?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut encoded)
        .ok()?;
    if encoded.len() as u64 > MANIFEST_LIMIT {
        return None;
    }
    let manifest: Manifest = serde_json::from_slice(&encoded).ok()?;
    if manifest.version != 1
        || !hex_field(&manifest.nonce, 32)
        || !hex_field(&manifest.database_sha256, 64)
    {
        return None;
    }
    if manifest.store != store {
        return None;
    }
    if path.file_name()?.to_str()? != name(&manifest)? {
        return None;
    }
    let mut entries = fs::read_dir(path)
        .ok()?
        .map(|entry| entry.ok().map(|e| e.file_name()))
        .collect::<Option<Vec<_>>>()?;
    entries.sort();
    if entries
        != [
            std::ffi::OsString::from("database"),
            std::ffi::OsString::from("manifest.json"),
        ]
    {
        return None;
    }
    if digest_file(&path.join("database"), owner).ok()? != manifest.database_sha256 {
        return None;
    }
    Some(Completed {
        path: path.into(),
        created_ns: manifest.created_ns,
        nonce: manifest.nonce,
    })
}
fn prune(
    root: &Path,
    store: &str,
    owner: &Metadata,
    keep: NonZeroUsize,
    published: &Path,
) -> Result<(), BackupError> {
    before_prune(root);
    let mut backups = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        if let Some(backup) = completed(&entry.path(), store, owner) {
            backups.push(backup);
        }
    }
    backups.sort_by(|a, b| {
        (b.path.as_path() == published)
            .cmp(&(a.path.as_path() == published))
            .then_with(|| b.created_ns.cmp(&a.created_ns))
            .then_with(|| b.nonce.cmp(&a.nonce))
    });
    for backup in backups.into_iter().skip(keep.get()) {
        if completed(&backup.path, store, owner).is_none() {
            continue;
        }
        fs::remove_file(backup.path.join("database"))?;
        fs::remove_file(backup.path.join("manifest.json"))?;
        fs::remove_dir(backup.path)?;
    }
    Ok(())
}

impl Store {
    pub fn backup_if_pending(
        &self,
        root: &Path,
        keep: NonZeroUsize,
    ) -> Result<BackupResult, BackupError> {
        // Pin the migration decision and copied pages to the same SQLite snapshot.
        let snapshot_guard = self.connection.unchecked_transaction()?;
        let pending_migrations = self.pending_migrations_snapshot()?;
        if pending_migrations.is_empty() {
            return Ok(BackupResult::NoPendingMigrations);
        }
        let owner = fs::metadata(&self.file)?;
        ensure_root(root, &owner)?;
        let store = base64::engine::general_purpose::STANDARD
            .encode(self.file.as_os_str().as_encoded_bytes());
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| BackupError::Metadata)?;
        let nonce = hex(&random);
        let pending = root.join(format!(".gateway-backup-pending-{nonce}"));
        create_directory(&pending)?;
        snapshot(&self.connection, &pending.join("database"))?;
        drop(snapshot_guard);
        let created_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BackupError::Metadata)?
            .as_nanos()
            .try_into()
            .map_err(|_| BackupError::Metadata)?;
        let manifest = Manifest {
            version: 1,
            store: store.clone(),
            created_ns,
            nonce,
            database_sha256: digest_file(&pending.join("database"), &owner)?,
        };
        use std::io::Write;
        let mut document = create_private_file(&pending.join("manifest.json"))?;
        document.write_all(&serde_json::to_vec(&manifest).map_err(|_| BackupError::Metadata)?)?;
        document.sync_all()?;
        File::open(&pending)?.sync_all()?;
        let directory_lock = lock_directory(root, &owner, Duration::from_secs(30))?;
        let final_path = root.join(name(&manifest).ok_or(BackupError::Metadata)?);
        // Rename may replace only the empty destination reserved by this operation.
        before_reserve(&final_path);
        create_directory(&final_path)?;
        let reservation = File::open(&final_path)?;
        before_publish(&final_path);
        publish(&pending, &final_path, &reservation, &owner, &directory_lock)?;
        prune(root, &store, &owner, keep, &final_path)?;
        Ok(BackupResult::Published)
    }
}

fn before_publish(_path: &Path) {
    #[cfg(test)]
    BEFORE_PUBLISH.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback(_path);
        }
    });
}
#[cfg(test)]
type PublishHook = Box<dyn FnOnce(&Path)>;
#[cfg(test)]
thread_local! { static BEFORE_PUBLISH: std::cell::RefCell<Option<PublishHook>> = const { std::cell::RefCell::new(None) }; }

fn before_reserve(_path: &Path) {
    #[cfg(test)]
    BEFORE_RESERVE.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback(_path);
        }
    });
}
#[cfg(test)]
thread_local! { static BEFORE_RESERVE: std::cell::RefCell<Option<PublishHook>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
#[path = "grants_backup_tests.rs"]
mod tests;

fn before_prune(_path: &Path) {
    #[cfg(test)]
    BEFORE_PRUNE.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback(_path);
        }
    });
}
#[cfg(test)]
thread_local! { static BEFORE_PRUNE: std::cell::RefCell<Option<PublishHook>> = const { std::cell::RefCell::new(None) }; }
