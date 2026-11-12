use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use super::Error;

pub trait Clock: Send + Sync {
    fn wall(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn wall(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0)
    }
}
struct HighWater {
    value: i64,
    persisted: i64,
    blocked_until: i64,
    persisting: bool,
    revoke_ticket: u64,
    revoked_ticket: u64,
}
#[cfg(test)]
type Hook = (std::thread::ThreadId, Arc<dyn Fn() + Send + Sync>);

pub(crate) struct Fence {
    #[cfg(test)]
    snapshot_hook: Mutex<Option<Hook>>,
    #[cfg(test)]
    persist_hook: Mutex<Option<Hook>>,
    #[cfg(test)]
    revoke_hook: Mutex<Option<Hook>>,
    clock: Arc<dyn Clock>,
    high: Mutex<HighWater>,
}
impl Fence {
    pub fn wall(&self) -> i64 {
        self.clock.wall()
    }
    pub fn new(clock: Arc<dyn Clock>, db: &Connection) -> Result<Self, Error> {
        let (value, blocked_until) = db.query_row(
            "SELECT value,rollback_until FROM clock_hw WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(Self {
            clock,
            #[cfg(test)]
            snapshot_hook: Mutex::new(None),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            #[cfg(test)]
            revoke_hook: Mutex::new(None),
            high: Mutex::new(HighWater {
                value,
                persisted: value,
                blocked_until,
                persisting: false,
                revoke_ticket: 0,
                revoked_ticket: 0,
            }),
        })
    }
    pub fn observe(&self, db: &Connection, persist: bool) -> Result<(i64, i64), Error> {
        let autonomous = db.is_autocommit();
        let (stored, blocked): (i64, i64) = db.query_row(
            "SELECT value,rollback_until FROM clock_hw WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        tracing::debug!(target:"gateway_oauth_clock_snapshot",class="read");
        #[cfg(test)]
        self.pause(true);
        let (wall, value, rollback, clear, write, claimed, revoke_ticket) = {
            let mut high = self.high.lock().map_err(|_| Error::Unavailable)?;
            let wall = self.clock.wall();
            high.value = high.value.max(stored).max(wall);
            high.blocked_until = high.blocked_until.max(blocked);
            if autonomous {
                high.persisted = high.persisted.max(stored);
            }
            let detected = wall < high.value.saturating_sub(5);
            if detected {
                if high.revoke_ticket == high.revoked_ticket || high.value > high.blocked_until {
                    high.revoke_ticket = high
                        .revoke_ticket
                        .checked_add(1)
                        .ok_or(Error::Unavailable)?;
                }
                high.blocked_until = high.value;
            }
            // Failed revocation stays pending even when the wall clock catches up.
            let rollback = high.revoke_ticket > high.revoked_ticket;
            let clear = high.blocked_until > 0 && wall >= high.blocked_until;
            let due = high.value.saturating_sub(high.persisted) >= 10;
            let claimed = autonomous && !rollback && !high.persisting && (persist || due);
            if claimed {
                high.persisting = true;
            }
            (
                wall,
                high.value,
                rollback,
                clear,
                persist || claimed,
                claimed,
                high.revoke_ticket,
            )
        };
        if rollback && !autonomous {
            return Err(Error::ClockRollback);
        }
        // Never hold the in-memory fence across SQLite: another transaction can need both.
        let result = (|| {
            if rollback {
                #[cfg(test)]
                self.pause_revoke();
                let tx = rusqlite::Transaction::new_unchecked(
                    db,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                let needs_revoke = self
                    .high
                    .lock()
                    .map_err(|_| Error::Unavailable)?
                    .revoked_ticket
                    < revoke_ticket;
                let mut changed = 0;
                if needs_revoke {
                    changed = tx.execute("UPDATE oauth_families SET revoked_at=?1,revoked_reason='clock_rollback' WHERE revoked_at IS NULL",[value])?;
                    tx.execute("UPDATE clock_hw SET value=MAX(value,?1),rollback_until=MAX(rollback_until,?1) WHERE id=1",[value])?;
                    if clear {
                        tx.execute("UPDATE clock_hw SET rollback_until=0 WHERE id=1 AND rollback_until<=?1",[wall])?;
                    }
                }
                tx.commit()?;
                if changed > 0 {
                    tracing::warn!(target:"gateway_oauth_clock",class="clock_rollback");
                }
            } else {
                if clear {
                    db.execute(
                        "UPDATE clock_hw SET rollback_until=0 WHERE id=1 AND rollback_until<=?1",
                        [wall],
                    )?;
                }
                if write {
                    tracing::debug!(target:"gateway_oauth_clock_persist",class="attempt");
                    #[cfg(test)]
                    self.pause(false);
                    db.execute(
                        "UPDATE clock_hw SET value=MAX(value,?1) WHERE id=1",
                        [value],
                    )?;
                }
            }
            Ok::<_, Error>(())
        })();
        {
            let mut high = self.high.lock().map_err(|_| Error::Unavailable)?;
            if claimed {
                high.persisting = false;
            }
            if result.is_ok() && autonomous && (write || rollback) {
                high.persisted = high.persisted.max(value);
            }
            if result.is_ok() && rollback {
                high.revoked_ticket = high.revoked_ticket.max(revoke_ticket);
            }
            if result.is_ok()
                && clear
                && high.blocked_until <= wall
                && high.revoke_ticket == high.revoked_ticket
            {
                high.blocked_until = 0;
            }
            if result.is_ok() && high.revoke_ticket != high.revoked_ticket {
                return Err(Error::ClockRollback);
            }
        }
        result?;
        Ok((wall, value))
    }
    #[cfg(test)]
    pub(super) fn set_hook(&self, snapshot: bool, hook: Arc<dyn Fn() + Send + Sync>) {
        let field = if snapshot {
            &self.snapshot_hook
        } else {
            &self.persist_hook
        };
        *field.lock().unwrap() = Some((std::thread::current().id(), hook));
    }
    #[cfg(test)]
    pub(super) fn set_revoke_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.revoke_hook.lock().unwrap() = Some((std::thread::current().id(), hook));
    }
    #[cfg(test)]
    fn pause_revoke(&self) {
        let hook = self.revoke_hook.lock().unwrap().clone();
        if let Some((owner, hook)) = hook {
            if owner == std::thread::current().id() {
                hook();
            }
        }
    }
    #[cfg(test)]
    fn pause(&self, snapshot: bool) {
        let field = if snapshot {
            &self.snapshot_hook
        } else {
            &self.persist_hook
        };
        let hook = field.lock().unwrap().clone();
        if let Some((owner, hook)) = hook {
            if owner == std::thread::current().id() {
                hook();
            }
        }
    }
    #[cfg(test)]
    pub(super) fn memory_available(&self) -> bool {
        self.high.try_lock().is_ok()
    }
    pub fn mint(&self, db: &Connection) -> Result<(i64, i64), Error> {
        let (wall, now) = self.observe(db, true)?;
        if wall
            < self
                .high
                .lock()
                .map_err(|_| Error::Unavailable)?
                .blocked_until
        {
            return Err(Error::Unavailable);
        }
        Ok((wall, now))
    }
}
