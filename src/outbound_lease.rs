use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::grants::{Error, Store};

pub struct OperationLease(File);

impl Drop for OperationLease {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl OperationLease {
    fn acquire(state_file: &Path, service: &str) -> io::Result<Option<Self>> {
        let parent = state_file
            .parent()
            .ok_or_else(|| io::Error::other("missing state directory"))?;
        let directory = parent.metadata()?;
        if directory.mode() & 0o022 != 0 || !directory.is_dir() {
            return Err(io::Error::other(
                "state directory must not be writable by other users",
            ));
        }
        let name = format!(
            "xmsg-gateway-{:x}.lease",
            Sha256::digest(service.as_bytes())
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(parent.join(name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != directory.uid()
            || metadata.nlink() != 1
        {
            return Err(io::Error::other("invalid operation lease file"));
        }
        match file.try_lock() {
            Ok(()) => Ok(Some(Self(file))),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

impl Store {
    pub fn try_operation_lease(&self, service: &str) -> Result<Option<OperationLease>, Error> {
        if service.trim().is_empty() {
            return Err(Error::InvalidBinding);
        }
        Ok(OperationLease::acquire(&self.file, service)?)
    }

    pub(crate) fn wait_operation_lease(
        &self,
        service: &str,
        budget: Duration,
    ) -> Result<OperationLease, Error> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(lease) = self.try_operation_lease(service)? {
                return Ok(lease);
            }
            if Instant::now() >= deadline {
                return Err(Error::OperationBusy);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
