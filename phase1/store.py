import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from cryptography.fernet import Fernet

from . import grants
from .auth import PRINCIPAL, SCOPES

MAX_OUTBOX = 1000


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def encode(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self._guard_local = threading.local()
        self.settings = None
        self.grant_enforcement = True
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        with self.guard():
            key_file = self.root / "key"
            if not key_file.exists() and (self.root / "state.sqlite3").exists():
                raise ValueError("existing state is missing its encryption key")
            if not key_file.exists():
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(Fernet.generate_key())
                    stream.flush()
                    os.fsync(stream.fileno())
            self.cipher = Fernet(key_file.read_bytes())
            fd = os.open(self.root / "state.sqlite3", os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            with self.db() as db:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS credentials (
                  id TEXT PRIMARY KEY, mode TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                  token BLOB);
                CREATE TABLE IF NOT EXISTS subscription (
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL,
                  url TEXT NOT NULL, secret BLOB NOT NULL, old_secret BLOB,
                  rotation_until REAL NOT NULL, expires REAL NOT NULL,
                  credential TEXT NOT NULL, active INTEGER NOT NULL,
                  verified_until REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox (
                  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                  occurrence TEXT UNIQUE NOT NULL, event_id TEXT UNIQUE NOT NULL,
                  body BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                  attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                  last_error TEXT);
                CREATE TABLE IF NOT EXISTS service_profile (
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1), service_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS service_grants (
                  id TEXT PRIMARY KEY, service_id TEXT NOT NULL, issuer TEXT NOT NULL,
                  subject TEXT NOT NULL, resource TEXT NOT NULL, hosted_client_id TEXT NOT NULL,
                  scope_ceiling TEXT NOT NULL, revision INTEGER NOT NULL, enabled INTEGER NOT NULL,
                  UNIQUE(service_id,issuer,subject,resource,hosted_client_id));
                CREATE UNIQUE INDEX IF NOT EXISTS one_enabled_grant ON service_grants(service_id) WHERE enabled=1;
                CREATE TABLE IF NOT EXISTS grant_replays (
                  event_id TEXT NOT NULL,old_grant_id TEXT,old_revision INTEGER,
                  new_grant_id TEXT NOT NULL,new_revision INTEGER NOT NULL,
                  operator TEXT NOT NULL,reason TEXT NOT NULL,recorded_at REAL NOT NULL);
                """)
                migrating = "accepted_grant_id" not in {
                    r["name"] for r in db.execute("PRAGMA table_info(outbox)")
                }
                for table, columns in {
                    "credentials": {"grant_id": "TEXT", "grant_revision": "INTEGER"},
                    "subscription": {"grant_id": "TEXT", "grant_revision": "INTEGER"},
                    "outbox": {
                        "accepted_grant_id": "TEXT",
                        "accepted_grant_revision": "INTEGER",
                        "dispatch_grant_id": "TEXT",
                        "dispatch_grant_revision": "INTEGER",
                    },
                }.items():
                    existing = {
                        r["name"]
                        for r in db.execute("PRAGMA table_info(" + table + ")")
                    }
                    for column, kind in columns.items():
                        if column not in existing:
                            db.execute(
                                "ALTER TABLE "
                                + table
                                + " ADD COLUMN "
                                + column
                                + " "
                                + kind
                            )
                if (
                    migrating
                    and not db.execute(
                        "SELECT 1 FROM credentials WHERE mode='local-test'"
                    ).fetchone()
                ):
                    db.execute(
                        "UPDATE outbox SET state='held_replay_required' WHERE state='pending'"
                    )

    def configure(self, settings):
        if self.settings is None:
            with self.guard(), self.db() as db:
                row = db.execute("SELECT service_id FROM service_profile").fetchone()
                if row and row["service_id"] != settings.service_id:
                    raise ValueError("state directory belongs to another service")
                db.execute(
                    "INSERT OR IGNORE INTO service_profile VALUES (1,?)",
                    (settings.service_id,),
                )
        elif self.settings.service_id != settings.service_id:
            raise ValueError("state directory belongs to another service")
        self.settings = settings
        self.grant_enforcement = settings.auth_mode != "local-test"

    def enroll_grant(self, settings, scopes):
        return grants.enroll(self, settings, scopes)

    def set_grant_enabled(self, identifier, enabled):
        return grants.set_enabled(self, identifier, enabled)

    def replay_event(self, event_id, operator, reason):
        return grants.replay(self, event_id, operator, reason)

    @contextmanager
    def guard(self):
        if getattr(self._guard_local, "held", False):
            yield
            return
        fd = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._guard_local.held = True
            try:
                yield
            finally:
                self._guard_local.held = False

    @contextmanager
    def db(self):
        database = quote(str((self.root / "state.sqlite3").resolve()), safe="/")
        connection = sqlite3.connect(
            "file:" + database + "?mode=rw", uri=True, timeout=15
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def issue(self):
        token = secrets.token_urlsafe(48)
        with self.guard(), self.db() as db:
            db.execute(
                "INSERT INTO credentials(id,mode) VALUES (?,?)",
                (digest(token), "local-test"),
            )
        return token

    def revoke(self, token):
        self.revoke_id(digest(token))

    def revoke_id(self, credential):
        with self.guard(), self.db() as db:
            db.execute("UPDATE credentials SET revoked=1 WHERE id=?", (credential,))

    def authenticate(self, token, oauth=None):
        credential = digest(token)
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM credentials WHERE id=?", (credential,)
            ).fetchone()
        if row and row["revoked"]:
            return None
        if oauth:
            self.configure(oauth.settings)
            claims = oauth.validate(token)
            if not claims:
                return None
            with self.guard(), self.db() as db:
                grant = grants.resolve(db, oauth.settings, claims, SCOPES)
                db.execute(
                    "INSERT INTO credentials(id,mode,token,grant_id,grant_revision) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET grant_id=excluded.grant_id,grant_revision=excluded.grant_revision",
                    (
                        credential,
                        "oauth",
                        self.cipher.encrypt(token.encode()),
                        grant["id"],
                        grant["revision"],
                    ),
                )
                row = db.execute(
                    "SELECT * FROM credentials WHERE id=?", (credential,)
                ).fetchone()
                return credential if row and not row["revoked"] else None
        return (
            credential
            if row and row["mode"] == "local-test" and not row["revoked"]
            else None
        )

    def credential_active(self, db, credential, oauth):
        row = db.execute(
            "SELECT * FROM credentials WHERE id=?", (credential,)
        ).fetchone()
        if not row or row["revoked"]:
            return False
        if row["mode"] == "oauth":
            if not oauth:
                return False
            claims = oauth.validate(self.cipher.decrypt(row["token"]).decode())
            if not claims:
                return False
            try:
                grant = grants.resolve(db, oauth.settings, claims, SCOPES)
            except grants.GrantDenied:
                return False
            return (
                grant["id"] == row["grant_id"]
                and grant["revision"] == row["grant_revision"]
            )
        return oauth is None and row["mode"] == "local-test"

    def emit(self, occurrence):
        if not occurrence or len(occurrence) > 128:
            raise ValueError("occurrence must be 1..128 characters")
        with self.guard(), self.db() as db:
            existing = db.execute(
                "SELECT event_id FROM outbox WHERE occurrence=?", (occurrence,)
            ).fetchone()
            if existing:
                return existing["event_id"]
            if db.execute("SELECT count(*) FROM outbox").fetchone()[0] >= MAX_OUTBOX:
                raise ValueError("outbox quota reached; no custody accepted")
            event_id = "xm_evt_" + secrets.token_hex(16)
            sequence = db.execute(
                "SELECT coalesce(max(sequence),0)+1 FROM outbox"
            ).fetchone()[0]
            event = {
                "eventId": event_id,
                "name": "xmsg.message.received.v1",
                "timestamp": datetime.now(UTC).isoformat(),
                "data": {
                    "message_id": "synthetic_" + digest(occurrence)[:24],
                    "mailbox": PRINCIPAL,
                    "origin": {"id": "synthetic", "node": "phase1-synthetic"},
                    "in_reply_to": None,
                    "preview": "Synthetic phase 1 event.",
                    "body_available": False,
                    "sequence": sequence,
                },
                "cursor": None,
            }
            grant = None
            if self.grant_enforcement:
                if self.settings:
                    grant = db.execute(
                        "SELECT * FROM service_grants WHERE service_id=? AND issuer=? AND subject=? "
                        "AND resource=? AND hosted_client_id=?",
                        (
                            self.settings.service_id,
                            self.settings.issuer,
                            self.settings.subject,
                            self.settings.resource,
                            self.settings.approved_hosted_oauth_client_id,
                        ),
                    ).fetchone()
            state = (
                "pending"
                if not self.grant_enforcement or (grant and grant["enabled"])
                else "held_grant_disabled"
                if grant
                else "held_unbound"
            )
            gid, revision = (grant["id"], grant["revision"]) if grant else (None, None)
            db.execute(
                "INSERT INTO outbox(occurrence,event_id,body,state,accepted_grant_id,accepted_grant_revision,"
                "dispatch_grant_id,dispatch_grant_revision) VALUES (?,?,?,?,?,?,?,?)",
                (
                    occurrence,
                    event_id,
                    encode(event),
                    state,
                    gid,
                    revision,
                    gid,
                    revision,
                ),
            )
            return event_id

    def entries(self):
        with self.db() as db:
            return [
                dict(row)
                for row in db.execute("SELECT * FROM outbox ORDER BY sequence")
            ]

    def health(self):
        with self.db() as db:
            row = db.execute("SELECT * FROM subscription").fetchone()
            state = (
                "none"
                if not row
                else "inactive"
                if not row["active"]
                else "expired"
                if row["expires"] <= time.time()
                else "active"
            )
            counts = {
                s: 0
                for s in (
                    "pending",
                    "accepted",
                    "dead",
                    "held_unbound",
                    "held_grant_disabled",
                    "held_replay_required",
                )
            }
            counts.update(
                dict(db.execute("SELECT state,count(*) FROM outbox GROUP BY state"))
            )
            return {"subscription": state, **counts}
