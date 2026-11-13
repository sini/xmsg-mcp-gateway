use super::{Error, Store};
use rusqlite::{Connection, OpenFlags};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn failure(class: &'static str) -> Error {
    tracing::warn!(target: "gateway_policy_store", recovery = class, "recovery failed");
    Error::Io(std::io::Error::other(class))
}

fn journal_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push("-journal");
    name.into()
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return false;
        }
    }
    before.len() == after.len()
        && matches!((before.modified(), after.modified()), (Ok(left), Ok(right)) if left == right)
}

fn private_directory(file: &Path, source: &Metadata) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(failure("backup-directory")),
    }
    let metadata = fs::symlink_metadata(file).map_err(|_| failure("backup-directory"))?;
    if !metadata.is_dir() {
        return Err(failure("backup-directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o700 || metadata.uid() != source.uid() {
            return Err(failure("backup-directory"));
        }
    }
    Ok(())
}

fn preserve(file: &Path, journal: &Path) -> Result<bool, Error> {
    let mut database = File::open(file).map_err(|_| failure("backup-source"))?;
    let mut rollback = File::open(journal).map_err(|_| failure("backup-source"))?;
    let database_before = database.metadata().map_err(|_| failure("backup-source"))?;
    let journal_before = rollback.metadata().map_err(|_| failure("backup-source"))?;
    if !database_before.is_file() || !journal_before.is_file() || journal_before.len() == 0 {
        return Err(failure("backup-source"));
    }
    let mut root = file.as_os_str().to_os_string();
    root.push(".recovery");
    let root = PathBuf::from(root);
    private_directory(&root, &database_before)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| failure("backup-directory"))?;
    let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = root.join(name);
    // A collision fails closed instead of reusing another recovery's evidence.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&directory)
        .map_err(|_| failure("backup-directory"))?;
    for (source, name) in [(&mut database, "database"), (&mut rollback, "journal")] {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut destination = options
            .open(directory.join(name))
            .map_err(|_| failure("backup-copy"))?;
        std::io::copy(source, &mut destination).map_err(|_| failure("backup-copy"))?;
        destination.sync_all().map_err(|_| failure("backup-sync"))?;
    }
    for (source, name, before) in [
        (&database, file, &database_before),
        (&rollback, journal, &journal_before),
    ] {
        let held = source.metadata().map_err(|_| failure("backup-changed"))?;
        let current = fs::metadata(name).map_err(|_| failure("backup-changed"))?;
        if !unchanged(before, &held) || !unchanged(before, &current) {
            return Err(failure("backup-changed"));
        }
    }
    File::open(&directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| failure("backup-sync"))?;
    File::open(&root)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| failure("backup-sync"))?;
    if let Some(parent) = root.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| failure("backup-sync"))?;
    }
    let mut header = [0; 8];
    let mut saved_journal =
        File::open(directory.join("journal")).map_err(|_| failure("backup-header"))?;
    let recognized = match saved_journal.read_exact(&mut header) {
        Ok(()) => header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7],
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(_) => return Err(failure("backup-header")),
    };
    Ok(recognized)
}

pub(super) fn recover(file: &Path) -> Result<(), Error> {
    let file = file.canonicalize().map_err(|_| failure("source"))?;
    let journal = journal_path(&file);
    let metadata = fs::metadata(&journal).map_err(|_| failure("journal"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(failure("journal"));
    }
    if !preserve(&file, &journal)? {
        return Err(failure("unrecognized-journal"));
    }
    let connection = Connection::open_with_flags(&file, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| failure("rollback"))?;
    connection
        .busy_timeout(Duration::from_secs(30))
        .map_err(|_| failure("rollback"))?;
    connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| failure("rollback"))?;
    let mut statement = connection
        .prepare("PRAGMA quick_check")
        .map_err(|_| failure("integrity"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| failure("integrity"))?;
    let results = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| failure("integrity"))?;
    if results != ["ok"] {
        return Err(failure("integrity"));
    }
    Store::validate_connection(&connection).map_err(|_| failure("schema"))?;
    drop(statement);
    connection.close().map_err(|_| failure("close"))?;
    tracing::info!(target: "gateway_policy_store", recovery = "complete", "rollback recovery complete");
    Ok(())
}
