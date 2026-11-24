use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};

type Snapshot = BTreeMap<PathBuf, (u64, u32, u32, u64, i64, i64, Option<[u8; 32]>)>;
fn tree(root: &Path) -> Option<Snapshot> {
    fn walk(base: &Path, path: &Path, result: &mut Snapshot) -> Option<()> {
        let m = fs::symlink_metadata(path).ok()?;
        let bytes = if m.is_file() {
            Some(Sha256::digest(fs::read(path).ok()?).into())
        } else if m.file_type().is_symlink() {
            Some(Sha256::digest(fs::read_link(path).ok()?.as_os_str().as_encoded_bytes()).into())
        } else {
            None
        };
        result.insert(
            path.strip_prefix(base).ok()?.into(),
            (
                m.ino(),
                m.mode(),
                m.uid(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                bytes,
            ),
        );
        if m.is_dir() {
            for entry in fs::read_dir(path).ok()? {
                walk(base, &entry.ok()?.path(), result)?;
            }
        }
        Some(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Some(result)
}
fn fixture() -> (tempfile::TempDir, PathBuf, Store) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("authority.db");
    let mut store = Store::initialize(&file).unwrap();
    store
        .enroll(
            "grant",
            &super::super::Binding {
                service: "service".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "subject".into(),
                hosted_client: "client".into(),
            },
        )
        .unwrap();
    (dir, file, store)
}
fn keep(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}
fn entries(root: &Path) -> Vec<PathBuf> {
    let mut result: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("manifest.json").is_file())
        .collect();
    result.sort();
    result
}
fn backup(store: &Store, root: &Path, n: usize) {
    assert_eq!(
        store.backup_if_pending(root, keep(n)).unwrap(),
        BackupResult::Published
    );
}

#[test]
fn retention_keeps_newest_completed_snapshot_and_at_least_one() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    for revision in 1..=3 {
        store
            .connection
            .execute("UPDATE grants SET revision=?1", [revision])
            .unwrap();
        backup(&store, &root, 1);
    }
    let completed = entries(&root);
    assert_eq!(
        completed.len(),
        1,
        "retention must keep at least the newest completed backup"
    );
    let c = Connection::open_with_flags(
        completed[0].join("database"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        c.query_row("SELECT revision FROM grants", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3,
        "retention pruned the newest snapshot"
    );
}

#[test]
fn retention_scopes_exact_store_identity_not_shared_directory_or_prefix() {
    let (dir, _, first) = fixture();
    let root = dir.path().join("backups");
    let other_file = dir.path().join("other.db");
    let other = Store::initialize(&other_file).unwrap();
    backup(&other, &root, 10);
    backup(&other, &root, 10);
    let foreign: Vec<_> = entries(&root)
        .into_iter()
        .map(|path| {
            let before = tree(&path);
            (path, before)
        })
        .collect();
    backup(&first, &root, 1);
    for (path, before) in foreign {
        assert_eq!(
            tree(&path),
            before,
            "retention pruned a foreign store backup"
        );
    }
    assert_eq!(entries(&root).len(), 3);
}

#[test]
fn retention_keeps_newest_historical_snapshot_alongside_current() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    for revision in 1..=3 {
        store
            .connection
            .execute("UPDATE grants SET revision=?1", [revision])
            .unwrap();
        backup(&store, &root, 2);
    }
    let mut retained: Vec<i64> = entries(&root)
        .into_iter()
        .map(|artifact| {
            Connection::open_with_flags(artifact.join("database"), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap()
                .query_row("SELECT revision FROM grants", [], |row| row.get(0))
                .unwrap()
        })
        .collect();
    retained.sort();
    assert_eq!(
        retained,
        [2, 3],
        "retention pruned the newest historical snapshot"
    );
}

#[test]
fn retention_keeps_current_publication_when_prior_clock_was_ahead() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    backup(&store, &root, 10);
    let original = entries(&root).pop().unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(original.join("manifest.json")).unwrap()).unwrap();
    document["created_ns"] = serde_json::json!(u64::MAX - 1);
    fs::write(
        original.join("manifest.json"),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    let old_name = original.file_name().unwrap().to_str().unwrap();
    let (before_nonce, nonce) = old_name.rsplit_once('-').unwrap();
    let (identity_prefix, old_time) = before_nonce.rsplit_once('-').unwrap();
    assert_eq!(old_time.len(), 16);
    let future = root.join(format!("{identity_prefix}-{:016x}-{nonce}", u64::MAX - 1));
    fs::rename(&original, future).unwrap();
    store
        .connection
        .execute("UPDATE grants SET revision=2", [])
        .unwrap();
    backup(&store, &root, 1);
    let retained = entries(&root);
    assert_eq!(retained.len(), 1);
    let c = Connection::open_with_flags(
        retained[0].join("database"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        c.query_row("SELECT revision FROM grants", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2,
        "a successful backup must retain the current rollback point despite clock skew"
    );
}

#[test]
fn retention_preserves_name_manifest_mismatch() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    backup(&store, &root, 10);
    let original = entries(&root).pop().unwrap();
    let altered = root.join(format!("{PREFIX}unmanaged"));
    fs::rename(original, &altered).unwrap();
    let before = tree(&altered);
    backup(&store, &root, 1);
    assert_eq!(
        tree(&altered),
        before,
        "retention deleted a name/manifest mismatch"
    );
}

#[test]
fn retention_preserves_altered_database_checksum() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    backup(&store, &root, 10);
    let altered = entries(&root).pop().unwrap();
    Connection::open(altered.join("database")).unwrap().execute_batch("CREATE TABLE operator_note(value TEXT); INSERT INTO operator_note VALUES('retain altered backup');").unwrap();
    let before = tree(&altered);
    backup(&store, &root, 1);
    assert_eq!(
        tree(&altered),
        before,
        "retention deleted a checksum-mismatched backup"
    );
}

#[test]
fn retention_preserves_unknown_extra_entries_and_symlinks() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    backup(&store, &root, 10);
    let altered = entries(&root).pop().unwrap();
    fs::write(altered.join("operator-note"), b"not managed by backup CLI").unwrap();
    let target = dir.path().join("unrelated");
    fs::write(&target, b"untouched").unwrap();
    let link = root.join(format!("{PREFIX}symlink"));
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let before = tree(&altered);
    let target_before = tree(&target);
    let link_before = tree(&link);
    let result = store.backup_if_pending(&root, keep(1));
    assert_eq!(
        tree(&altered),
        before,
        "unknown extra entries must preserve their completed directory"
    );
    assert_eq!(tree(&target), target_before);
    assert_eq!(tree(&link), link_before);
    assert_eq!(result.unwrap(), BackupResult::Published);
}

#[test]
fn publication_failure_never_prunes_preexisting_completed_backups() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    for _ in 0..3 {
        backup(&store, &root, 10);
    }
    let previous: Vec<_> = entries(&root)
        .into_iter()
        .map(|path| {
            let before = tree(&path);
            (path, before)
        })
        .collect();
    BEFORE_PUBLISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|path| {
            fs::write(path.join("operator-marker"), b"refuse this publication").unwrap();
        }))
    });
    let result = store.backup_if_pending(&root, keep(1));
    File::open(&root)
        .unwrap()
        .try_lock()
        .expect("publication failure must release directory coordination");
    for (path, before) in previous {
        assert_eq!(
            tree(&path),
            before,
            "publication failure pruned an existing completed backup"
        );
    }
    assert!(matches!(result, Err(BackupError::Publication)));
    assert!(
        fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".gateway-backup-pending-")),
        "failed publication must retain its available pending evidence"
    );
}

#[test]
fn publication_refuses_changed_empty_destination_reservation() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    let replaced = Arc::new(Mutex::new(None));
    let capture = replaced.clone();
    BEFORE_PUBLISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            fs::remove_dir(path).unwrap();
            create_directory(path).unwrap();
            *capture.lock().unwrap() =
                Some((path.to_path_buf(), fs::metadata(path).unwrap().ino()));
        }))
    });
    let result = store.backup_if_pending(&root, keep(1));
    let (path, inode) = replaced.lock().unwrap().clone().unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().ino(),
        inode,
        "publication clobbered a changed destination reservation"
    );
    assert!(fs::read_dir(path).unwrap().next().is_none());
    assert!(matches!(result, Err(BackupError::Publication)));
}

#[test]
fn publication_refuses_existing_destination_name_without_adoption() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    let collision = Arc::new(Mutex::new(None));
    let capture = collision.clone();
    BEFORE_RESERVE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            create_directory(path).unwrap();
            *capture.lock().unwrap() =
                Some((path.to_path_buf(), fs::metadata(path).unwrap().ino()));
        }))
    });
    let result = store.backup_if_pending(&root, keep(1));
    let (path, inode) = collision.lock().unwrap().clone().unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().ino(),
        inode,
        "publication adopted and clobbered an existing destination"
    );
    assert!(fs::read_dir(path).unwrap().next().is_none());
    assert!(result.is_err());
}

#[test]
fn pending_backup_refuses_nonprivate_directory_without_repair() {
    let (dir, file, store) = fixture();
    let root = dir.path().join("backups");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let before = tree(&root);
    let source_before = tree(&file);
    let result = store.backup_if_pending(&root, keep(1));
    assert_eq!(
        tree(&root),
        before,
        "nonprivate backup directory was modified or repaired"
    );
    assert_eq!(tree(&file), source_before);
    assert!(matches!(result, Err(BackupError::Directory)));
}

#[test]
fn publication_and_retention_hold_backup_directory_coordination() {
    let (dir, _, store) = fixture();
    let root = dir.path().join("backups");
    BEFORE_PUBLISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|destination| {
            let probe = File::open(destination.parent().unwrap()).unwrap();
            let observed = probe.try_lock();
            if observed.is_ok() {
                probe.unlock().unwrap();
            }
            assert!(
                matches!(observed, Err(std::fs::TryLockError::WouldBlock)),
                "publication must hold the backup-directory lock"
            );
        }))
    });
    BEFORE_PRUNE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|directory| {
            let probe = File::open(directory).unwrap();
            let observed = probe.try_lock();
            if observed.is_ok() {
                probe.unlock().unwrap();
            }
            assert!(
                matches!(observed, Err(std::fs::TryLockError::WouldBlock)),
                "retention must hold the backup-directory lock"
            );
        }))
    });
    backup(&store, &root, 1);
    let released = File::open(&root).unwrap();
    released
        .try_lock()
        .expect("backup must release directory coordination on return");
}

#[test]
fn held_directory_coordination_has_bounded_refusal_without_mutation() {
    let (dir, file, _) = fixture();
    let root = dir.path().join("backups");
    let owner = fs::metadata(&file).unwrap();
    ensure_root(&root, &owner).unwrap();
    let held = File::open(&root).unwrap();
    held.try_lock().unwrap();
    let before = tree(&root);
    let started = Instant::now();
    let result = lock_directory(&root, &owner, Duration::ZERO);
    assert_eq!(tree(&root), before);
    assert!(matches!(result, Err(BackupError::Busy)));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "zero-wait lock refusal must be bounded"
    );
    held.unlock().unwrap();
    lock_directory(&root, &owner, Duration::ZERO).unwrap();
}

#[test]
fn unsupported_directory_lock_error_is_refused_not_accepted() {
    fn unsupported(_: &File) -> Result<(), std::fs::TryLockError> {
        Err(std::fs::TryLockError::Error(
            std::io::ErrorKind::Unsupported.into(),
        ))
    }
    let (dir, file, _) = fixture();
    let root = dir.path().join("backups");
    let owner = fs::metadata(&file).unwrap();
    ensure_root(&root, &owner).unwrap();
    let before = tree(&root);
    let result = lock_directory_with(&root, &owner, Duration::ZERO, unsupported);
    assert_eq!(tree(&root), before);
    assert!(
        matches!(result, Err(BackupError::Coordination(error)) if error.kind() == std::io::ErrorKind::Unsupported),
        "unsupported directory locking must be refused"
    );
}

#[test]
fn concurrent_publishers_retain_a_completed_rollback_point() {
    use std::sync::Condvar;
    let (dir, file, store) = fixture();
    drop(store);
    let root = dir.path().join("backups");
    let ready = Arc::new((Mutex::new(0usize), Condvar::new()));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let ready = ready.clone();
            let file = file.clone();
            let root = root.clone();
            workers.push(scope.spawn(move || {
                let (count, changed) = &*ready;
                let mut count = count.lock().unwrap();
                *count += 1;
                changed.notify_all();
                let deadline = Instant::now() + Duration::from_secs(15);
                while *count != 2 {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(!remaining.is_zero(), "concurrent publisher start deadline");
                    count = changed.wait_timeout(count, remaining).unwrap().0;
                }
                drop(count);
                Store::open_readonly(&file)
                    .unwrap()
                    .backup_if_pending(&root, keep(1))
            }));
        }
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), BackupResult::Published);
        }
    });
    let retained = entries(&root);
    assert_eq!(
        retained.len(),
        1,
        "concurrent publishers removed every rollback point"
    );
    let c = Connection::open_with_flags(
        retained[0].join("database"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        c.query_row("SELECT revision FROM grants", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn waiting_publisher_resnapshots_after_coordination_and_retains_revision_two() {
    use std::sync::mpsc::channel;
    let (dir, file, store) = fixture();
    drop(store);
    let root = dir.path().join("backups");
    std::thread::scope(|scope| {
        let (entered, reached) = channel();
        let (resume, released) = channel();
        let file_a = file.clone();
        let root_a = root.clone();
        let first = scope.spawn(move || {
            BEFORE_COORDINATION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |_| {
                    entered.send(()).unwrap();
                    released
                        .recv_timeout(Duration::from_secs(15))
                        .expect("publisher coordination release deadline");
                }))
            });
            Store::open_readonly(&file_a)
                .unwrap()
                .backup_if_pending(&root_a, keep(1))
        });
        reached
            .recv_timeout(Duration::from_secs(15))
            .expect("publisher did not reach coordination boundary");
        Connection::open(&file)
            .unwrap()
            .execute("UPDATE grants SET revision=2", [])
            .unwrap();
        backup(&Store::open_readonly(&file).unwrap(), &root, 1);
        resume.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), BackupResult::Published);
    });
    let retained = entries(&root);
    assert_eq!(retained.len(), 1);
    let c = Connection::open_with_flags(
        retained[0].join("database"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(c.query_row("SELECT revision FROM grants", [], |row| row.get::<_,i64>(0)).unwrap(), 2,
        "waiting publisher must resnapshot after coordination instead of restoring stale revision one");
}

#[test]
fn final_complete_recheck_never_publishes_or_prunes_after_waiting() {
    use std::io::Write;
    let (dir, file, store) = fixture();
    let root = dir.path().join("backups");
    for _ in 0..3 {
        backup(&store, &root, 10);
    }
    let previous: Vec<_> = entries(&root)
        .into_iter()
        .map(|p| {
            let before = tree(&p);
            (p, before)
        })
        .collect();
    let key_file = dir.path().join("events-key");
    let mut key_output = create_private_file(&key_file).unwrap();
    key_output.write_all(&[7; 32]).unwrap();
    key_output.sync_all().unwrap();
    drop(key_output);
    let event_key = crate::event_store::EventKey::load(&key_file).unwrap();
    BEFORE_COORDINATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_| {
            let mut migrated = Store::open(&file).unwrap();
            migrated.migrate_custody().unwrap();
            migrated.migrate_outbound().unwrap();
            migrated.migrate_retirement().unwrap();
            migrated.migrate_events(&event_key).unwrap();
            migrated.migrate_profiles().unwrap();
            migrated.migrate_attachments().unwrap();
            migrated.migrate_authorization_server().unwrap();
        }))
    });
    let result = store.backup_if_pending(&root, keep(1));
    for (p, before) in previous {
        assert_eq!(
            tree(&p),
            before,
            "final complete recheck pruned a prior snapshot"
        );
    }
    assert_eq!(
        entries(&root).len(),
        3,
        "final complete recheck published an unnecessary snapshot"
    );
    assert_eq!(result.unwrap(), BackupResult::NoPendingMigrations);
}

#[test]
fn directory_guard_unlocks_with_retained_open_description_on_success_and_error() {
    fn return_from_operation(_guard: DirectoryLock, fail: bool) -> Result<(), BackupError> {
        if fail {
            return Err(BackupError::Publication);
        }
        Ok(())
    }
    let (dir, file, _) = fixture();
    let root = dir.path().join("backups");
    let owner = fs::metadata(&file).unwrap();
    ensure_root(&root, &owner).unwrap();
    for fail in [false, true] {
        let guard = lock_directory(&root, &owner, Duration::ZERO).unwrap();
        assert!(matches!(
            File::open(&root).unwrap().try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        // A retained duplicate models the shared description in a fork/exec window.
        let inherited = guard.try_clone().unwrap();
        let result = return_from_operation(guard, fail);
        let probe = File::open(&root).unwrap();
        let released = probe.try_lock();
        assert!(
            released.is_ok(),
            "guard must explicitly unlock while a retained open description remains alive"
        );
        assert_eq!(result.is_err(), fail);
        assert!(inherited.metadata().unwrap().is_dir());
        probe.unlock().unwrap();
        drop(inherited);
    }
}

#[test]
fn backup_snapshot_matches_pending_decision_during_wal_writer_commit() {
    let (dir, file, store) = fixture();
    store
        .connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    let root = dir.path().join("backups");
    let (start, begin) = std::sync::mpsc::sync_channel(1);
    let (committed, done) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let source = file.clone();
        let writer = scope.spawn(move || {
            let connection = Connection::open(source).unwrap();
            connection.busy_timeout(Duration::from_secs(15)).unwrap();
            begin
                .recv_timeout(Duration::from_secs(15))
                .expect("writer start acknowledgement");
            connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE snapshot_migration_marker(value INTEGER NOT NULL); INSERT INTO snapshot_migration_marker VALUES(7); UPDATE grants SET revision=7; COMMIT;").unwrap();
            committed.send(()).unwrap();
        });
        BEFORE_SNAPSHOT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_| {
                start.send(()).unwrap();
                done.recv_timeout(Duration::from_secs(15))
                    .expect("WAL writer commit acknowledgement");
            }));
        });
        let result = store.backup_if_pending(&root, keep(1));
        writer.join().unwrap();
        let artifacts = entries(&root);
        assert_eq!(artifacts.len(), 1);
        let copied: i64 = Connection::open_with_flags(
            artifacts[0].join("database"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
        .query_row("SELECT revision FROM grants", [], |row| row.get(0))
        .unwrap();
        let copied_schema: i64 = Connection::open_with_flags(
            artifacts[0].join("database"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='snapshot_migration_marker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
        assert_eq!(
            copied_schema, 0,
            "backup must copy the pending-decision snapshot across a WAL writer commit"
        );
        assert_eq!(copied, 1);

        let live: i64 = Connection::open_with_flags(&file, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT revision FROM grants", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            live, 7,
            "the independent writer must have committed before copying"
        );
        let live_schema: i64 = Connection::open_with_flags(&file, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT value FROM snapshot_migration_marker", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            live_schema, 7,
            "the independent WAL schema change must be committed"
        );
        assert_eq!(result.unwrap(), BackupResult::Published);
    });
}

#[test]
fn readable_completed_files_are_ignored_without_consuming_retention() {
    const EFFECT: &str =
        "readable completed entries must remain untouched and not consume valid backup slots";
    for filename in ["database", "manifest.json"] {
        for mode in [0o640, 0o604] {
            for historical in [true, false] {
                let (dir, file, store) = fixture();
                let owner = fs::metadata(&file).unwrap();
                let root = dir.path().join("backups");
                let valid = if historical {
                    backup(&store, &root, 10);
                    entries(&root).pop()
                } else {
                    None
                };
                backup(&store, &root, 10);
                let invalid = entries(&root)
                    .into_iter()
                    .find(|path| Some(path) != valid.as_ref())
                    .unwrap();
                let mut document: Manifest =
                    serde_json::from_slice(&fs::read(invalid.join("manifest.json")).unwrap())
                        .unwrap();
                document.created_ns = u64::MAX - 1;
                fs::write(
                    invalid.join("manifest.json"),
                    serde_json::to_vec(&document).unwrap(),
                )
                .unwrap();
                let future = root.join(name(&document).unwrap());
                fs::rename(invalid, &future).unwrap();
                assert!(
                    completed(&future, &document.store, &owner).is_some(),
                    "all non-permission recognition fields must be valid"
                );
                fs::set_permissions(future.join(filename), fs::Permissions::from_mode(mode))
                    .unwrap();
                let invalid_before = tree(&future);
                let valid_before = valid.as_ref().map(|path| tree(path));
                let source_before = tree(&file);
                let old_paths = entries(&root);
                let wanted = if historical { 2 } else { 1 };
                let result = store.backup_if_pending(&root, keep(wanted));
                assert_eq!(tree(&future), invalid_before, "{EFFECT}");
                if let Some(path) = valid.as_ref() {
                    assert_eq!(tree(path), valid_before.unwrap(), "{EFFECT}");
                }
                let after = entries(&root);
                let private: Vec<_> = after
                    .iter()
                    .filter(|path| {
                        fs::metadata(path).unwrap().permissions().mode() & 0o777 == 0o700
                            && ["database", "manifest.json"].iter().all(|file| {
                                let metadata = fs::symlink_metadata(path.join(file)).unwrap();
                                metadata.is_file()
                                    && metadata.uid() == owner.uid()
                                    && metadata.permissions().mode() & 0o777 == 0o600
                            })
                    })
                    .collect();
                assert_eq!(private.len(), wanted, "{EFFECT}");
                let fresh: Vec<_> = private
                    .into_iter()
                    .filter(|path| !old_paths.contains(path))
                    .collect();
                assert_eq!(fresh.len(), 1, "a pending store requires a fresh private valid snapshot even with only an invalid entry");
                assert_eq!(tree(&file), source_before);
                assert_eq!(result.unwrap(), BackupResult::Published);
            }
        }
    }
}
