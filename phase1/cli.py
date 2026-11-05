import argparse
import json
import os
import sys
import tomllib
from pathlib import Path

import uvicorn

from .app import create_app
from .config import Settings
from .store import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-local-test")
    issue.add_argument("--output", required=True, type=Path)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("credential_id")
    emit = commands.add_parser("emit")
    emit.add_argument("occurrence_id")
    commands.add_parser("status")
    commands.add_parser("reset-binding")
    retry = commands.add_parser("retry-dead")
    retry.add_argument("event_id")
    commands.add_parser("serve")
    args = parser.parse_args()
    config = tomllib.loads(args.config.read_text()) if args.config else {}
    if args.state:
        config["state_dir"] = args.state
    settings = Settings(**config)
    store = Store(settings.state_dir)
    match args.command:
        case "issue-local-test":
            token = store.issue()
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(token + "\n")
            print(
                "Local-test credential written to the requested file; no hosted auth enabled."
            )
        case "revoke":
            store.revoke_id(args.credential_id)
            print("Credential revoked.")
        case "emit":
            print(store.emit(args.occurrence_id))
        case "status":
            print(
                json.dumps(
                    {
                        "health": store.health(),
                        "outbox": [
                            {
                                k: row[k]
                                for k in ("event_id", "state", "attempts", "last_error")
                            }
                            for row in store.entries()
                        ],
                    }
                )
            )
        case "reset-binding":
            with store.guard(), store.db() as db:
                db.execute("DELETE FROM subscription")
            print(
                "Binding cleared; pending custody retained for the next verified subscription."
            )
        case "retry-dead":
            with store.guard(), store.db() as db:
                db.execute(
                    "UPDATE outbox SET state='pending',attempts=0,next_attempt=0 WHERE event_id=? AND state='dead'",
                    (args.event_id,),
                )
            print("Selected dead letter rearmed with original event ID.")
        case "serve":
            uvicorn.run(
                create_app(settings, store, run_worker=True),
                host=settings.bind,
                port=settings.port,
                access_log=False,
                log_level="critical",
            )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print(
            "Configuration or local state error; inspect settings locally.",
            file=sys.stderr,
        )
        sys.exit(1)
