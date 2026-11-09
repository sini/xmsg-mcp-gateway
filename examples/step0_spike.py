"""Throwaway hosted-integration probe. Synthetic events only; never connects to xmsg."""

import argparse
import os
import sys
import tomllib
from pathlib import Path
from typing import Literal

import uvicorn

from phase1.app import create_app
from phase1.config import Settings
from phase1.store import Store


class SpikeSettings(Settings):
    # The shipped local-test profile keeps its original loopback-only constraint.
    auth_mode: Literal["oauth", "bearer"] = "oauth"


def require_bearer_opt_in(settings, allow_bearer):
    if settings.auth_mode == "bearer" and not allow_bearer:
        raise ValueError("example bearer mode requires --allow-bearer")


def create_spike(settings, *, allow_bearer=False, **kwargs):
    require_bearer_opt_in(settings, allow_bearer)
    return create_app(settings, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--allow-bearer",
        action="store_true",
        help="explicitly enable bearer authentication for this throwaway probe",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-bearer")
    issue.add_argument("--output", type=Path, required=True)
    emit = commands.add_parser("emit")
    emit.add_argument("occurrence_id")
    commands.add_parser("serve")
    args = parser.parse_args()
    settings = SpikeSettings(**tomllib.loads(args.config.read_text()))
    require_bearer_opt_in(settings, args.allow_bearer)
    if args.command == "issue-bearer" and settings.auth_mode != "bearer":
        raise ValueError("issue-bearer requires example bearer mode")
    store = Store(settings.state_dir)
    if args.command == "issue-bearer":
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(store.issue() + "\n")
    elif args.command == "emit":
        print(store.emit(args.occurrence_id))
    else:
        uvicorn.run(
            create_spike(
                settings, allow_bearer=args.allow_bearer, store=store, run_worker=True
            ),
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
            "Invalid spike configuration or local state; check settings locally.",
            file=sys.stderr,
        )
        sys.exit(1)
