use super::{hash, random, token_shape, Error, Outcome, Server, SCHEMA_VERSION};
use crate::grants::{Authorization, Store};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

type AccessRow = (String, String, i64, Option<i64>, Option<i64>);
type CodeRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
);
type RefreshRow = (
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

macro_rules! mint_snapshot {
    ($server:expr,$store:expr,$tx:ident) => {
        match $server.clock.mint(&$tx) {
            Ok(time) => time,
            Err(Error::ClockRollback) => {
                drop($tx);
                $server.clock.observe(&$store.connection, true)?;
                return Err(Error::Unavailable);
            }
            Err(error) => return Err(error),
        }
    };
}

pub(crate) fn validate(db: &Connection) -> Result<(), rusqlite::Error> {
    for sql in [
        "SELECT code_hash,client_id,redirect_uri,code_challenge,scope,resource,grant_id,grant_revision,liveness_ok_at,expires_at,used_at,family_id FROM oauth_codes LIMIT 0",
        "SELECT id,grant_id,client_id,subject,scope,resource,created_at,absolute_expires_at,last_refresh_at,liveness_ok_at,access_expires_at,last_mint_graced,last_liveness_outcome,liveness_read_at,liveness_ticket,liveness_applied,revoked_at,revoked_reason FROM oauth_families LIMIT 0",
        "SELECT hash,family_id,issued_at,rotated_at,superseded_at,successor_hash,successor_used_at,retried_at FROM oauth_refresh_tokens LIMIT 0",
        "SELECT hash,family_id,refresh_hash,issued_at,expires_at,revoked_at,first_used_at FROM oauth_access_tokens LIMIT 0",
        "SELECT token_family FROM event_subscriptions LIMIT 0", "SELECT id,value,rollback_until FROM clock_hw LIMIT 0",
        "SELECT seq,from_grant,to_grant,at,operator,reason,abandoned FROM events_cutover LIMIT 0",
        "SELECT family_id,at FROM oauth_rotation_log LIMIT 0",
    ]{db.prepare(sql)?;}
    Ok(())
}
impl Store {
    pub fn require_authorization_server_ready(&self) -> Result<(), Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(Error::Configuration);
        }
        validate(&self.connection)?;
        Ok(())
    }
    pub fn migrate_authorization_server(&mut self) -> Result<(), Error> {
        self.require_profiles_ready()
            .map_err(|_| Error::Configuration)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != crate::grants::EVENTS_SCHEMA_VERSION {
            return Err(Error::Configuration);
        }
        tx.execute_batch("CREATE TABLE oauth_codes(code_hash TEXT PRIMARY KEY NOT NULL,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,code_challenge TEXT NOT NULL,scope TEXT NOT NULL,resource TEXT NOT NULL,grant_id TEXT NOT NULL REFERENCES grants(id),grant_revision INTEGER NOT NULL,liveness_ok_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER,family_id TEXT);
        CREATE TABLE oauth_families(id TEXT PRIMARY KEY NOT NULL,grant_id TEXT NOT NULL REFERENCES grants(id),client_id TEXT NOT NULL,subject TEXT NOT NULL,scope TEXT NOT NULL,resource TEXT NOT NULL,created_at INTEGER NOT NULL,absolute_expires_at INTEGER NOT NULL,last_refresh_at INTEGER NOT NULL,liveness_ok_at INTEGER NOT NULL,access_expires_at INTEGER NOT NULL,last_mint_graced INTEGER NOT NULL CHECK(last_mint_graced IN (0,1)),last_liveness_outcome TEXT NOT NULL DEFAULT 'positive' CHECK(last_liveness_outcome IN ('positive','unavailable','indeterminate')),liveness_read_at INTEGER,liveness_ticket INTEGER NOT NULL DEFAULT 0,liveness_applied INTEGER NOT NULL DEFAULT 0,revoked_at INTEGER,revoked_reason TEXT CHECK(revoked_reason IN ('refresh_reuse','code_replay','grant_disabled','revocation_endpoint','kanidm_denied','absolute','evicted','clock_rollback')));
        CREATE TABLE oauth_refresh_tokens(hash TEXT PRIMARY KEY NOT NULL,family_id TEXT NOT NULL REFERENCES oauth_families(id),issued_at INTEGER NOT NULL,rotated_at INTEGER,superseded_at INTEGER,successor_hash TEXT,successor_used_at INTEGER,retried_at INTEGER);
        CREATE UNIQUE INDEX oauth_one_current_refresh ON oauth_refresh_tokens(family_id) WHERE rotated_at IS NULL AND superseded_at IS NULL;
        CREATE TABLE oauth_access_tokens(hash TEXT PRIMARY KEY NOT NULL,family_id TEXT NOT NULL REFERENCES oauth_families(id),refresh_hash TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER,first_used_at INTEGER);
        CREATE TABLE oauth_rotation_log(family_id TEXT NOT NULL,at INTEGER NOT NULL);
        CREATE TABLE clock_hw(id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER NOT NULL,rollback_until INTEGER NOT NULL DEFAULT 0);
        INSERT INTO clock_hw(id,value) VALUES(1,0);
        CREATE TABLE events_cutover(seq INTEGER PRIMARY KEY AUTOINCREMENT,from_grant TEXT NOT NULL,to_grant TEXT NOT NULL,at INTEGER NOT NULL,operator TEXT NOT NULL,reason TEXT NOT NULL,abandoned INTEGER NOT NULL CHECK(abandoned IN(0,1)));
        ALTER TABLE event_subscriptions RENAME TO event_subscriptions_before_as;
        CREATE TABLE event_subscriptions(id TEXT PRIMARY KEY NOT NULL,owner_key TEXT NOT NULL UNIQUE,service TEXT NOT NULL,issuer TEXT NOT NULL,resource TEXT NOT NULL,subject TEXT NOT NULL,hosted_client TEXT NOT NULL,bus TEXT NOT NULL,mailbox TEXT NOT NULL,grant_id TEXT NOT NULL,grant_revision INTEGER NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),expires INTEGER NOT NULL,url BLOB NOT NULL,secret BLOB NOT NULL,old_secret BLOB,bearer BLOB,rotation_until INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL CHECK(status IN ('verifying','active','disabled')),verified_at INTEGER,callback_cursor INTEGER NOT NULL DEFAULT 0,observation_checkpoint INTEGER NOT NULL DEFAULT 0,token_family TEXT REFERENCES oauth_families(id),CHECK((bearer IS NULL)!=(token_family IS NULL)));
        INSERT INTO event_subscriptions SELECT *,NULL FROM event_subscriptions_before_as;
        DROP TABLE event_subscriptions_before_as;")?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        self.require_authorization_server_ready()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Family {
    pub id: String,
    pub grant: String,
    pub client: String,
    pub subject: String,
    pub scope: String,
    pub resource: String,
    pub absolute: i64,
    pub refreshed: i64,
    pub live: i64,
    pub access: i64,
    pub outcome: String,
    pub revoked: Option<i64>,
    pub reason: Option<String>,
}
fn family(db: &Connection, id: &str) -> Result<Family, Error> {
    db.query_row("SELECT id,grant_id,client_id,subject,scope,resource,absolute_expires_at,last_refresh_at,liveness_ok_at,access_expires_at,last_liveness_outcome,revoked_at,revoked_reason FROM oauth_families WHERE id=?1",[id],|r|Ok(Family{id:r.get(0)?,grant:r.get(1)?,client:r.get(2)?,subject:r.get(3)?,scope:r.get(4)?,resource:r.get(5)?,absolute:r.get(6)?,refreshed:r.get(7)?,live:r.get(8)?,access:r.get(9)?,outcome:r.get(10)?,revoked:r.get(11)?,reason:r.get(12)?})).optional()?.ok_or(Error::InvalidGrant)
}
#[derive(serde::Serialize)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct Pair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: &'static str,
    pub scope: String,
}
pub(crate) struct Admission {
    pub policy: crate::outbound::Policy,
    pub authority: Authorization,
    pub expires: i64,
    pub family: String,
}
fn scopes_cover(actual: &str, required: &[String]) -> bool {
    required
        .iter()
        .all(|r| actual.split_ascii_whitespace().any(|a| a == r))
}
impl Server {
    pub(crate) fn effective_now(&self) -> Result<i64, Error> {
        let store = self.store()?;
        self.clock
            .observe(&store.connection, false)
            .map(|(_, now)| now)
    }
    pub(crate) fn store(&self) -> Result<Store, Error> {
        Store::open(&self.file).map_err(|_| Error::Unavailable)
    }
    fn authority(&self, db: &Connection, grant: &str) -> Result<Authorization, Error> {
        db.query_row("SELECT id,revision FROM grants WHERE id=?1 AND service=?2 AND issuer=?3 AND resource=?4 AND subject=?5 AND hosted_client=?6 AND enabled=1",params![grant,self.binding.service,self.binding.issuer,self.binding.resource,self.binding.subject,self.binding.hosted_client],|r|Ok(Authorization{grant_id:r.get(0)?,revision:r.get(1)?})).optional()?.ok_or(Error::Denied)
    }
    pub(crate) fn local_authority(&self) -> Result<Authorization, Error> {
        let store = self.store()?;
        store.connection.query_row("SELECT id,revision FROM grants WHERE service=?1 AND issuer=?2 AND resource=?3 AND subject=?4 AND hosted_client=?5 AND enabled=1",params![self.binding.service,self.binding.issuer,self.binding.resource,self.binding.subject,self.binding.hosted_client],|r|Ok(Authorization{grant_id:r.get(0)?,revision:r.get(1)?})).optional()?.ok_or(Error::Denied)
    }
    fn live_family(&self, db: &Connection, id: &str, now: i64) -> Result<Family, Error> {
        let f = family(db, id)?;
        if f.revoked.is_some() && f.reason.as_deref() == Some("grant_disabled") {
            self.authority(db, &f.grant)?;
            return Err(Error::InvalidGrant);
        }

        if f.revoked.is_some()
            || now >= f.absolute
            || now >= f.refreshed.saturating_add(self.config.refresh_idle_secs)
            || f.client != self.binding.hosted_client
            || f.subject != self.binding.subject
            || f.resource != self.binding.resource
            || !scopes_cover(&f.scope, &self.scopes)
        {
            return Err(Error::InvalidGrant);
        }
        Ok(f)
    }
    #[cfg(test)]
    pub(crate) fn admit(&self, token: &str) -> Result<Admission, Error> {
        if !token_shape(token, "xgw_at_") {
            return Err(Error::InvalidGrant);
        }
        let store = self.store()?;
        self.admit_in_store(&store, token)
    }
    pub(crate) fn admit_in_store(&self, store: &Store, token: &str) -> Result<Admission, Error> {
        if !token_shape(token, "xgw_at_") {
            return Err(Error::InvalidGrant);
        }
        self.clock.observe(&store.connection, false)?;
        let digest = hash(token);
        for write in [false, true] {
            let tx = rusqlite::Transaction::new_unchecked(
                &store.connection,
                if write {
                    TransactionBehavior::Immediate
                } else {
                    TransactionBehavior::Deferred
                },
            )?;
            let (_, now) = match self.clock.observe(&tx, false) {
                Ok(time) => time,
                Err(Error::ClockRollback) => {
                    drop(tx);
                    self.clock.observe(&store.connection, true)?;
                    return Err(Error::InvalidGrant);
                }
                Err(error) => return Err(error),
            };
            let row:Option<AccessRow>=tx.query_row("SELECT family_id,refresh_hash,expires_at,revoked_at,first_used_at FROM oauth_access_tokens WHERE hash=?1",[&digest],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let (id, pair, expires, revoked, used) = row.ok_or(Error::InvalidGrant)?;
            if revoked.is_some() || expires <= now {
                return Err(Error::InvalidGrant);
            }
            let f = self.live_family(&tx, &id, now)?;
            let superseded: Option<Option<i64>> = tx
                .query_row(
                    "SELECT superseded_at FROM oauth_refresh_tokens WHERE hash=?1 AND family_id=?2",
                    params![pair, id],
                    |r| r.get(0),
                )
                .optional()?;
            if !matches!(superseded, Some(None)) {
                return Err(Error::InvalidGrant);
            }
            let authority = self.authority(&tx, &f.grant)?;
            let policy = store
                .outbound_policy(&f.grant)
                .map_err(|_| Error::Unavailable)?;
            if used.is_none() && !write {
                drop(tx);
                tracing::debug!(target:"gateway_oauth_admission_upgrade",class="required");
                #[cfg(test)]
                {
                    let hook = self.upgrade_barrier.lock().unwrap().clone();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                continue;
            }
            tracing::debug!(target:"gateway_oauth_admission",class="validated_snapshot",sampled_now=now,marking=write);
            #[cfg(test)]
            {
                let hook = self.admission_barrier.lock().unwrap().clone();
                if let Some(hook) = hook {
                    hook(now);
                }
            }

            if used.is_none() {
                if tx.execute("UPDATE oauth_access_tokens SET first_used_at=?2 WHERE hash=?1 AND first_used_at IS NULL",params![digest,now])?!=1{return Err(Error::InvalidGrant)}
                let pred: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM oauth_refresh_tokens WHERE successor_hash=?1)",
                    [&pair],
                    |r| r.get(0),
                )?;
                let changed=tx.execute("UPDATE oauth_refresh_tokens SET successor_used_at=COALESCE(successor_used_at,?2) WHERE successor_hash=?1",params![pair,now])?;
                if pred && changed != 1 {
                    return Err(Error::InvalidGrant);
                }
            }
            tx.commit()?;
            return Ok(Admission {
                policy,
                authority,
                expires,
                family: id,
            });
        }
        Err(Error::InvalidGrant)
    }
    pub(crate) fn delivery_read_due(&self, id: &str) -> Result<bool, Error> {
        let store = self.store()?;
        let (_, now) = self.clock.observe(&store.connection, false)?;
        let f = self.live_family(&store.connection, id, now)?;
        self.authority(&store.connection, &f.grant)?;
        let bound = f.access.max(
            f.live
                .saturating_add(self.config.access_ttl_secs)
                .saturating_add(if f.outcome == "positive" {
                    0
                } else {
                    self.config.liveness.grace_secs
                }),
        );
        Ok(bound.saturating_sub(now) <= 600)
    }
    pub(crate) fn subscription_expiry(&self, id: &str, requested: i64) -> Result<i64, Error> {
        let store = self.store()?;
        let (_, now) = self.clock.observe(&store.connection, false)?;
        let f = self.live_family(&store.connection, id, now)?;
        self.authority(&store.connection, &f.grant)?;
        Ok(requested
            .min(f.absolute)
            .min(f.refreshed.saturating_add(self.config.refresh_idle_secs)))
    }
    pub(crate) fn verify_family(&self, id: &str) -> Result<(Family, i64), Error> {
        let store = self.store()?;
        let (_, now) = self.clock.observe(&store.connection, false)?;
        let f = self.live_family(&store.connection, id, now)?;
        self.authority(&store.connection, &f.grant)?;
        let bound = f
            .access
            .max(
                f.live
                    .saturating_add(self.config.access_ttl_secs)
                    .saturating_add(if f.outcome == "positive" {
                        0
                    } else {
                        self.config.liveness.grace_secs
                    }),
            )
            .min(f.absolute)
            .min(f.refreshed.saturating_add(self.config.refresh_idle_secs));
        if now >= bound {
            return Err(Error::InvalidGrant);
        }
        Ok((f, bound))
    }
    pub(crate) fn claim(&self, id: &str, dispatch: bool) -> Result<Option<(i64, i64)>, Error> {
        let mut store = self.store()?;
        self.clock.mint(&store.connection)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (start, _) = mint_snapshot!(self, store, tx);
        let result = if dispatch {
            tx.query_row("UPDATE oauth_families SET liveness_ticket=liveness_ticket+1,liveness_read_at=?2 WHERE id=?1 AND revoked_at IS NULL AND (liveness_read_at IS NULL OR liveness_read_at<=?2-300) RETURNING liveness_ticket",params![id,start],|r|r.get(0)).optional()?
        } else {
            tx.query_row("UPDATE oauth_families SET liveness_ticket=liveness_ticket+1 WHERE id=?1 AND revoked_at IS NULL RETURNING liveness_ticket",[id],|r|r.get(0)).optional()?
        };
        tx.commit()?;
        Ok(result.map(|n| (n, start)))
    }
    pub(crate) fn apply_liveness(
        &self,
        id: &str,
        ticket: i64,
        start: i64,
        outcome: Outcome,
    ) -> Result<(), Error> {
        let mut store = self.store()?;
        self.clock.observe(&store.connection, true)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, now) = mint_snapshot!(self, store, tx);
        match outcome {
            Outcome::Negative => {
                tx.execute("UPDATE oauth_families SET revoked_at=?2,revoked_reason='kanidm_denied',liveness_applied=MAX(liveness_applied,?3) WHERE id=?1 AND revoked_at IS NULL",params![id,now,ticket])?;
            }
            Outcome::Positive => {
                tx.execute("UPDATE oauth_families SET liveness_ok_at=?2,last_liveness_outcome='positive',liveness_applied=?3 WHERE id=?1 AND revoked_at IS NULL AND liveness_applied<?3",params![id,start,ticket])?;
            }
            other => {
                tx.execute("UPDATE oauth_families SET last_liveness_outcome=?2,liveness_applied=?3 WHERE id=?1 AND revoked_at IS NULL AND liveness_applied<?3",params![id,other.text(),ticket])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) async fn check_liveness(&self, id: &str, dispatch: bool) -> Result<(), Error> {
        if let Some((n, start)) = self.claim(id, dispatch)? {
            let outcome = self.liveness.read(start).await;
            #[cfg(test)]
            {
                let hook = self.liveness_barrier.lock().unwrap().clone();
                if let Some(hook) = hook {
                    hook(n, start, outcome);
                }
            }

            tracing::debug!(target:"gateway_oauth_liveness_result",class=outcome.text(),ticket=n,observation_start=start);
            self.apply_liveness(id, n, start, outcome)?;
        }
        Ok(())
    }
    fn expiry(&self, f: &Family, now: i64) -> Result<(i64, bool), Error> {
        let grace = f.outcome != "positive";
        let expires = if grace {
            now.saturating_add(self.config.access_ttl_secs).min(
                f.live
                    .saturating_add(self.config.access_ttl_secs)
                    .saturating_add(self.config.liveness.grace_secs),
            )
        } else {
            f.live.saturating_add(self.config.access_ttl_secs)
        }
        .min(f.absolute);
        if grace && expires <= now.saturating_add(60) {
            return Err(Error::Unavailable);
        }
        if expires <= now {
            return Err(Error::InvalidGrant);
        }
        Ok((expires, grace))
    }
    fn pair(&self, db: &Connection, f: &Family, now: i64) -> Result<Pair, Error> {
        let (expires, grace) = self.expiry(f, now)?;
        let access = random("xgw_at_")?;
        let refresh = random("xgw_rt_")?;
        db.execute(
            "INSERT INTO oauth_refresh_tokens(hash,family_id,issued_at) VALUES(?1,?2,?3)",
            params![hash(&refresh), f.id, now],
        )?;
        db.execute("INSERT INTO oauth_access_tokens(hash,family_id,refresh_hash,issued_at,expires_at) VALUES(?1,?2,?3,?4,?5)",params![hash(&access),f.id,hash(&refresh),now,expires])?;
        db.execute("UPDATE oauth_families SET access_expires_at=?2,last_mint_graced=?3,last_refresh_at=?4 WHERE id=?1",params![f.id,expires,grace,now])?;
        Ok(Pair {
            access_token: access,
            refresh_token: refresh,
            expires_in: expires - now,
            token_type: "Bearer",
            scope: f.scope.clone(),
        })
    }
    pub(crate) fn issue_code(
        &self,
        authority: &Authorization,
        redirect: &str,
        challenge: &str,
        scope: &str,
        live: i64,
    ) -> Result<String, Error> {
        let mut store = self.store()?;
        self.clock.mint(&store.connection)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, now) = mint_snapshot!(self, store, tx);
        if self.authority(&tx, &authority.grant_id)? != *authority {
            return Err(Error::Denied);
        }
        let code = random("xgw_ac_")?;
        tx.execute("INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,code_challenge,scope,resource,grant_id,grant_revision,liveness_ok_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![hash(&code),self.config.client.id,redirect,challenge,scope,self.binding.resource,authority.grant_id,authority.revision,live,now+60])?;
        tx.commit()?;
        Ok(code)
    }
    pub(crate) fn exchange(
        &self,
        code: &str,
        redirect: &str,
        verifier: &str,
        resource: Option<&str>,
    ) -> Result<Pair, Error> {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        if !token_shape(code, "xgw_ac_")
            || !(43..=128).contains(&verifier.len())
            || !verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Error::InvalidGrant);
        }
        let mut store = self.store()?;
        self.clock.mint(&store.connection)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, now) = mint_snapshot!(self, store, tx);
        let row:Option<CodeRow>=tx.query_row("SELECT redirect_uri,code_challenge,scope,grant_id,grant_revision,liveness_ok_at,expires_at,used_at,family_id FROM oauth_codes WHERE code_hash=?1 AND client_id=?2",params![hash(code),self.config.client.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
        let (bound_redirect, challenge, scope, grant, revision, live, expires, used, old_family) =
            row.ok_or(Error::InvalidGrant)?;
        if used.is_some() {
            if let Some(id) = old_family {
                tx.execute("UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?2),revoked_reason=COALESCE(revoked_reason,'code_replay') WHERE id=?1",params![id,now])?;
            }
            tx.commit()?;
            return Err(Error::InvalidGrant);
        }
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        if expires <= now
            || bound_redirect != redirect
            || challenge != expected
            || resource.is_some_and(|r| r != self.binding.resource)
            || self.authority(&tx, &grant)?.revision != revision
        {
            return Err(Error::InvalidGrant);
        }
        if tx.execute("UPDATE oauth_codes SET used_at=?2 WHERE code_hash=?1 AND used_at IS NULL AND expires_at>?2",params![hash(code),now])?!=1{return Err(Error::InvalidGrant)}
        let id = random("family_")?;
        tx.execute("INSERT INTO oauth_families(id,grant_id,client_id,subject,scope,resource,created_at,absolute_expires_at,last_refresh_at,liveness_ok_at,access_expires_at,last_mint_graced) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?7,?9,0,0)",params![id,grant,self.binding.hosted_client,self.binding.subject,scope,self.binding.resource,now,now+self.config.refresh_absolute_secs,live])?;
        tx.execute(
            "UPDATE oauth_codes SET family_id=?2 WHERE code_hash=?1",
            params![hash(code), id],
        )?;
        let f = family(&tx, &id)?;
        let pair = self.pair(&tx, &f, now)?;
        tx.execute("UPDATE oauth_families SET revoked_at=?2,revoked_reason='evicted' WHERE id IN (SELECT id FROM oauth_families WHERE grant_id=?1 AND revoked_at IS NULL ORDER BY last_refresh_at DESC,rowid DESC LIMIT -1 OFFSET ?3)",params![grant,now,self.config.max_families as i64])?;
        self.prune(&tx, now)?;
        tx.commit()?;
        Ok(pair)
    }
    pub(crate) async fn refresh(&self, token: &str) -> Result<Pair, Error> {
        if !token_shape(token, "xgw_rt_") {
            return Err(Error::InvalidGrant);
        }
        let digest = hash(token);
        let store = self.store()?;
        let id: String = store
            .connection
            .query_row(
                "SELECT family_id FROM oauth_refresh_tokens WHERE hash=?1",
                [&digest],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::InvalidGrant)?;
        let (_, now) = self.clock.mint(&store.connection)?;
        let f = family(&store.connection, &id)?;
        if f.revoked.is_some() {
            return Err(Error::InvalidGrant);
        }
        if now >= f.absolute {
            store.connection.execute("UPDATE oauth_families SET revoked_at=?2,revoked_reason='absolute' WHERE id=?1 AND revoked_at IS NULL",params![id,now])?;
            return Err(Error::InvalidGrant);
        }
        let f = self.live_family(&store.connection, &id, now)?;
        self.authority(&store.connection, &f.grant)?;
        self.rotation_limit(&store.connection, &id, now)?;
        drop(store);
        self.check_liveness(&id, false).await?;
        let mut store = self.store()?;
        self.clock.mint(&store.connection)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, now) = mint_snapshot!(self, store, tx);
        let f = self.live_family(&tx, &id, now)?;
        self.authority(&tx, &f.grant)?;
        self.rotation_limit(&tx, &id, now)?;
        let row:Option<RefreshRow>=tx.query_row("SELECT rotated_at,superseded_at,successor_hash,successor_used_at,retried_at FROM oauth_refresh_tokens WHERE hash=?1 AND family_id=?2",params![digest,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (rotated, superseded, successor, used, retried) = row.ok_or(Error::InvalidGrant)?;
        if superseded.is_some()
            || rotated.is_some_and(|t| now - t > 30)
            || (rotated.is_some() && (retried.is_some() || used.is_some()))
        {
            tx.execute("UPDATE oauth_families SET revoked_at=?2,revoked_reason='refresh_reuse' WHERE id=?1 AND revoked_at IS NULL",params![id,now])?;
            tx.commit()?;
            tracing::info!(target:"gateway_oauth_refresh",class="reuse");
            return Err(Error::InvalidGrant);
        }
        if rotated.is_some() {
            let successor = successor.ok_or(Error::InvalidGrant)?;
            if tx.execute("UPDATE oauth_refresh_tokens SET superseded_at=?2 WHERE hash=?1 AND rotated_at IS NULL AND superseded_at IS NULL",params![successor,now])?!=1 {
                tx.execute("UPDATE oauth_families SET revoked_at=?2,revoked_reason='refresh_reuse' WHERE id=?1 AND revoked_at IS NULL",params![id,now])?;tx.commit()?;tracing::info!(target:"gateway_oauth_refresh",class="reuse","refresh completed");return Err(Error::InvalidGrant)
            }
            tx.execute(
                "UPDATE oauth_access_tokens SET revoked_at=?2 WHERE refresh_hash=?1",
                params![successor, now],
            )?;
        } else {
            tx.execute(
                "UPDATE oauth_refresh_tokens SET rotated_at=?2 WHERE hash=?1",
                params![digest, now],
            )?;
            tx.execute("UPDATE oauth_refresh_tokens SET successor_used_at=COALESCE(successor_used_at,?2) WHERE successor_hash=?1",params![digest,now])?;
        }
        let pair = self.pair(&tx, &f, now)?;
        tx.execute("UPDATE oauth_refresh_tokens SET successor_hash=?2,retried_at=CASE WHEN ?3 THEN ?4 ELSE retried_at END WHERE hash=?1",params![digest,hash(&pair.refresh_token),rotated.is_some(),now])?;
        tx.execute(
            "INSERT INTO oauth_rotation_log VALUES(?1,?2)",
            params![id, now],
        )?;
        tx.execute("DELETE FROM oauth_refresh_tokens WHERE hash IN (SELECT hash FROM oauth_refresh_tokens WHERE family_id=?1 AND (rotated_at IS NOT NULL OR superseded_at IS NOT NULL) ORDER BY issued_at DESC,rowid DESC LIMIT -1 OFFSET ?2)",params![id,self.config.max_refresh_rows as i64])?;
        self.prune(&tx, now)?;
        tx.commit()?;
        let class = if rotated.is_some() { "retry" } else { "rotate" };
        tracing::info!(target:"gateway_oauth_refresh",class=class,"refresh completed");
        Ok(pair)
    }
    fn rotation_limit(&self, db: &Connection, id: &str, now: i64) -> Result<(), Error> {
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM oauth_rotation_log WHERE family_id=?1 AND at>?2-3600",
            params![id, now],
            |r| r.get(0),
        )?;
        if count >= self.config.rotations_per_hour as i64 {
            return Err(Error::RateLimited);
        }
        Ok(())
    }
    fn prune(&self, db: &Connection, now: i64) -> Result<(), Error> {
        db.execute(
            "DELETE FROM oauth_access_tokens WHERE expires_at<?1-30",
            [now],
        )?;
        db.execute("DELETE FROM oauth_codes WHERE expires_at<?1-60", [now])?;
        db.execute("DELETE FROM oauth_rotation_log WHERE at<=?1-3600", [now])?;
        Ok(())
    }
    pub(crate) fn revoke(&self, token: &str) -> Result<(), Error> {
        let store = self.store()?;
        let (_, now) = self.clock.observe(&store.connection, true)?;
        let table = if token_shape(token, "xgw_at_") {
            "oauth_access_tokens"
        } else if token_shape(token, "xgw_rt_") {
            "oauth_refresh_tokens"
        } else {
            return Ok(());
        };
        store.connection.execute(&format!("UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?2),revoked_reason=COALESCE(revoked_reason,'revocation_endpoint') WHERE id IN(SELECT family_id FROM {table} WHERE hash=?1)"),params![hash(token),now])?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cutover {
    Complete,
    Busy,
    Unread { from: i64, to: i64 },
}
impl Store {
    pub fn cutover_events(
        &mut self,
        from: &str,
        to: &str,
        operator: &str,
        reason: &str,
        abandon: bool,
        at: i64,
    ) -> Result<Cutover, Error> {
        self.require_authorization_server_ready()?;
        if from == to
            || [from, to, operator, reason]
                .iter()
                .any(|s| s.is_empty() || s.len() > 512 || s.chars().any(char::is_control))
        {
            return Err(Error::Configuration);
        }
        let binding = |id: &str| {
            self.connection.query_row(
                "SELECT service,resource,subject,revision FROM grants WHERE id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
        };
        let first = binding(from)?;
        let second = binding(to)?;
        if first.0 != second.0 || first.1 != second.1 || first.2 != second.2 {
            return Err(Error::Configuration);
        }
        let Some(_lease) = self
            .try_operation_lease(&first.0)
            .map_err(|_| Error::Unavailable)?
        else {
            return Ok(Cutover::Busy);
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let unread = |id: &str| {
            tx.query_row("SELECT COUNT(*) FROM custody_items c LEFT JOIN event_observations seen ON seen.event_id=c.event_id WHERE c.grant_id=?1 AND c.text IS NOT NULL AND c.expires_at>?2 AND seen.event_id IS NULL",params![id,at],|r|r.get::<_,i64>(0))
        };
        let old = unread(from)?;
        let new = unread(to)?;
        if !abandon && (old != 0 || new != 0) {
            return Ok(Cutover::Unread { from: old, to: new });
        }
        if abandon {
            tx.execute("INSERT INTO event_release_audit(event_id,grant_id,old_revision,new_revision,operator,reason) SELECT c.event_id,c.grant_id,c.grant_revision,c.grant_revision,?4,'cutover-abandon' FROM custody_items c LEFT JOIN event_observations seen ON seen.event_id=c.event_id WHERE c.grant_id IN(?1,?2) AND c.text IS NOT NULL AND c.expires_at>?3 AND seen.event_id IS NULL",params![from,to,at,operator])?;
        }
        tx.execute("INSERT INTO events_cutover(from_grant,to_grant,at,operator,reason,abandoned) VALUES(?1,?2,?3,?4,?5,?6)",params![from,to,at,operator,reason,abandon])?;
        tx.commit()?;
        Ok(Cutover::Complete)
    }
    pub(crate) fn validate_cutover_selection(&self, selected: Option<&str>) -> Result<(), Error> {
        if self
            .selected_cutover_grant()?
            .as_deref()
            .is_some_and(|expected| Some(expected) != selected)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub(crate) fn selected_cutover_grant(&self) -> Result<Option<String>, Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < SCHEMA_VERSION {
            return Ok(None);
        }
        Ok(self
            .connection
            .query_row(
                "SELECT to_grant FROM events_cutover ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?)
    }
}
