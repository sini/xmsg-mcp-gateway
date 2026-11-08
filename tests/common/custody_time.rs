use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn at(seconds: i64) -> SystemTime {
    let offset = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        UNIX_EPOCH.checked_sub(offset)
    } else {
        UNIX_EPOCH.checked_add(offset)
    }
    .expect("fixture timestamp is not representable")
}
