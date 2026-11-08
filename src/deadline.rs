use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
#[error("invalid lifetime deadline")]
pub(crate) struct InvalidDeadline;

pub(crate) fn window(at: SystemTime, lifetime: i64) -> Result<(i64, i64), InvalidDeadline> {
    if lifetime <= 0 {
        return Err(InvalidDeadline);
    }
    let elapsed = at.duration_since(UNIX_EPOCH).map_err(|_| InvalidDeadline)?;
    let observed = i64::try_from(elapsed.as_secs()).map_err(|_| InvalidDeadline)?;
    let expires = observed
        .checked_add(lifetime)
        .and_then(|deadline| deadline.checked_add(i64::from(elapsed.subsec_nanos() != 0)))
        .ok_or(InvalidDeadline)?;
    Ok((observed, expires))
}
