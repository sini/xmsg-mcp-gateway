"""THROWAWAY SQLite model of the approved local grant/replay contract.

Run directly to exercise the model. No serving path imports this module.
Owner methods below have no transport; no public administration API is modeled.
"""

import json
import sqlite3
import tempfile
from pathlib import Path
from uuid import uuid4


class Grants:
    def __init__(self, filename):
        self.db = sqlite3.connect(filename)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY, service TEXT UNIQUE NOT NULL,
                issuer TEXT NOT NULL, subject TEXT NOT NULL,
                resource TEXT NOT NULL, hosted_client TEXT NOT NULL,
                revision INTEGER NOT NULL, enabled INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS work (
                id TEXT PRIMARY KEY, grant_id TEXT NOT NULL,
                accepted_revision INTEGER NOT NULL,
                dispatch_revision INTEGER NOT NULL, state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replay_audit (
                work_id TEXT NOT NULL, old_revision INTEGER NOT NULL,
                new_revision INTEGER NOT NULL, owner TEXT NOT NULL,
                reason TEXT NOT NULL
            );
        """)

    def owner_provision(self, service, binding):
        with self.db:
            self.db.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, 1, 0)",
                (str(uuid4()), service, *binding),
            )

    def owner_set_enabled(self, service, enabled):
        with self.db:
            self.db.execute(
                "UPDATE grants SET enabled=?, revision=revision+1 WHERE service=?",
                (int(enabled), service),
            )
            if not enabled:
                self.db.execute(
                    "UPDATE work SET state='held' WHERE state='queued' "
                    "AND grant_id=(SELECT id FROM grants WHERE service=?)",
                    (service,),
                )

    def resolve(self, service, binding):
        try:
            row = self.db.execute(
                "SELECT * FROM grants WHERE service=? AND enabled=1 "
                "AND issuer=? AND subject=? AND resource=? AND hosted_client=?",
                (service, *binding),
            ).fetchone()
            return dict(row) if row else None
        except sqlite3.Error:
            return None

    def accept(self, service, binding):
        with self.db:
            # The write lock covers lookup and acceptance as one transaction.
            self.db.execute("BEGIN IMMEDIATE")
            grant = self.resolve(service, binding)
            if grant is None:
                return None
            ident = str(uuid4())
            self.db.execute(
                "INSERT INTO work VALUES (?, ?, ?, ?, 'queued')",
                (ident, grant["id"], grant["revision"], grant["revision"]),
            )
            return ident

    def dispatch_check(self, ident):
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                row = self.db.execute(
                    "SELECT w.state, w.dispatch_revision, g.enabled, g.revision "
                    "FROM work w JOIN grants g ON g.id=w.grant_id WHERE w.id=?",
                    (ident,),
                ).fetchone()
                allowed = bool(
                    row
                    and row["state"] == "queued"
                    and row["enabled"]
                    and row["dispatch_revision"] == row["revision"]
                )
                if row and not allowed and row["state"] == "queued":
                    self.db.execute("UPDATE work SET state='held' WHERE id=?", (ident,))
                return allowed
        except sqlite3.Error:
            return False

    def owner_replay(self, ident, owner, reason):
        if not owner or not reason:
            raise ValueError("replay requires owner and reason")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT w.*, g.enabled, g.revision FROM work w "
                "JOIN grants g ON g.id=w.grant_id WHERE w.id=?",
                (ident,),
            ).fetchone()
            if not row or row["state"] != "held" or not row["enabled"]:
                raise ValueError("only held work with an enabled grant can replay")
            self.db.execute(
                "INSERT INTO replay_audit VALUES (?, ?, ?, ?, ?)",
                (ident, row["dispatch_revision"], row["revision"], owner, reason),
            )
            self.db.execute(
                "UPDATE work SET dispatch_revision=?, state='queued' WHERE id=?",
                (row["revision"], ident),
            )


def main():
    with tempfile.TemporaryDirectory(prefix="grant-prototype-") as scratch:
        filename = Path(scratch) / "PROTOTYPE.sqlite"
        grants = Grants(filename)
        xmsg = (
            "https://broker.example",
            "fixture-owner",
            "https://xmsg.example/mcp",
            "hosted-X",
        )
        hindsight = (
            "https://broker.example",
            "fixture-owner",
            "https://memory.example/mcp",
            "hosted-H",
        )
        assert grants.resolve("xmsg", xmsg) is None
        grants.owner_provision("xmsg", xmsg)
        grants.owner_provision("hindsight", hindsight)
        assert grants.resolve("xmsg", xmsg) is None
        assert grants.resolve("hindsight", hindsight) is None
        grants.owner_set_enabled("xmsg", True)
        grants.owner_set_enabled("hindsight", True)
        a, b = (
            grants.accept("hindsight", hindsight),
            grants.accept("hindsight", hindsight),
        )
        assert a and b and grants.dispatch_check(a)
        assert grants.resolve("xmsg", hindsight) is None
        assert grants.resolve("hindsight", xmsg) is None
        assert grants.resolve("hindsight", (*hindsight[:3], "other-client")) is None
        grants.owner_set_enabled("hindsight", False)
        # New token digests never enter this identity-based authority lookup.
        assert grants.accept("hindsight", hindsight) is None
        assert grants.accept("xmsg", xmsg) is not None
        grants.owner_set_enabled("hindsight", True)
        assert not grants.dispatch_check(a) and not grants.dispatch_check(b)
        assert grants.accept("hindsight", hindsight) is not None
        grants.owner_replay(a, "fixture-operator", "selected replay")
        assert grants.dispatch_check(a) and not grants.dispatch_check(b)
        row = grants.db.execute("SELECT * FROM work WHERE id=?", (a,)).fetchone()
        assert (
            row["id"] == a
            and row["accepted_revision"] == 2
            and row["dispatch_revision"] == 4
        )
        audit = grants.db.execute("SELECT * FROM replay_audit").fetchall()
        assert len(audit) == 1 and audit[0]["work_id"] == a
        grants.db.close()
        grants = Grants(filename)
        assert grants.dispatch_check(a) and not grants.dispatch_check(b)
        grants.db.close()
        assert grants.resolve("hindsight", hindsight) is None
        assert not grants.dispatch_check(a)
    print(
        json.dumps(
            {
                "no_token_enrollment": True,
                "enrollment_starts_disabled": True,
                "service_and_client_isolation": True,
                "disabled_binding_rejects_refreshed_identity": True,
                "reenable_holds_old_work": True,
                "selected_replay_preserves_identity": True,
                "replay_audited": True,
                "restart_preserves_state": True,
                "lookup_outage_fails_closed": True,
            }
        )
    )


if __name__ == "__main__":
    main()
