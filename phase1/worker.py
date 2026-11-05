import time

from .transport import HTTPS, signed_post


class Worker:
    def __init__(self, store, http=None, oauth=None):
        self.store = store
        self.http = http or HTTPS()
        self.oauth = oauth

    def once(self):
        with self.store.guard(), self.store.db() as db:
            subscription = db.execute("SELECT * FROM subscription").fetchone()
            if (
                not subscription
                or not subscription["active"]
                or subscription["expires"] <= time.time()
                or not self.store.credential_active(
                    db, subscription["credential"], self.oauth
                )
            ):
                return False
            event = db.execute(
                "SELECT * FROM outbox WHERE state='pending' ORDER BY sequence LIMIT 1"
            ).fetchone()
            if not event or event["next_attempt"] > time.time():
                return False
            if event["attempts"] >= 5:
                db.execute(
                    "UPDATE outbox SET state='dead',last_error='attempts_exhausted' WHERE event_id=?",
                    (event["event_id"],),
                )
                return True
            attempts = event["attempts"] + 1
            db.execute(
                "UPDATE outbox SET attempts=?,next_attempt=? WHERE event_id=?",
                (attempts, time.time() + min(2**attempts, 300), event["event_id"]),
            )
            db.commit()
            keys = [self.store.cipher.decrypt(subscription["secret"]).decode()]
            if (
                subscription["old_secret"]
                and subscription["rotation_until"] > time.time()
            ):
                keys.append(
                    self.store.cipher.decrypt(subscription["old_secret"]).decode()
                )
            try:
                status, _ = signed_post(
                    self.http,
                    subscription["url"],
                    event["body"],
                    event["event_id"],
                    subscription["id"],
                    keys,
                )
                # Redirects and permanent failures are terminal, never followed or retried.
                accepted = 200 <= status < 300
                retryable = status in (408, 429) or 500 <= status < 600
                error = None if accepted else "http_" + str(status)
            except (OSError, ValueError):
                accepted, retryable, error = False, True, "transport_failed"
            state = (
                "accepted"
                if accepted
                else "pending"
                if retryable and attempts < 5
                else "dead"
            )
            db.execute(
                "UPDATE outbox SET state=?,attempts=?,next_attempt=?,last_error=? WHERE event_id=?",
                (
                    state,
                    attempts,
                    time.time() + min(2**attempts, 300),
                    error,
                    event["event_id"],
                ),
            )
            return True
