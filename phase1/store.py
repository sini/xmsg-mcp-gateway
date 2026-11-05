import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet

from .auth import PRINCIPAL

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
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        with self.guard():
            key_file = self.root / "key"
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
                """)

    @contextmanager
    def guard(self):
        fd = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.root / "state.sqlite3", timeout=15)
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
            if not oauth.validate(token):
                return None
            with self.guard(), self.db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO credentials(id,mode,token) VALUES (?,?,?)",
                    (credential, "oauth", self.cipher.encrypt(token.encode())),
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
            return bool(
                oauth and oauth.validate(self.cipher.decrypt(row["token"]).decode())
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
            db.execute(
                "INSERT INTO outbox(occurrence,event_id,body) VALUES (?,?,?)",
                (occurrence, event_id, encode(event)),
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
            counts = {s: 0 for s in ("pending", "accepted", "dead")}
            counts.update(
                dict(db.execute("SELECT state,count(*) FROM outbox GROUP BY state"))
            )
            return {"subscription": state, **counts}
