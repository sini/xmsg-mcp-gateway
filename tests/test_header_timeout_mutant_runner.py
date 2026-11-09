"""Forced timeout controls for the mutation harness, without Rust compilation."""

import importlib.util
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def runner(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "header_mutant_runner", scripts / "header_timeout_mutants.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hang_class_timeout_kills_owned_group_and_requires_fast_control(
    runner, tmp_path, monkeypatch
):
    nonce = "forced-timeout-control"
    marker = f"header-timeout nonce={nonce}"
    budget = 1
    baseline = runner.run_cell(
        [sys.executable, "-c", f"print({marker!r})"],
        cwd=tmp_path,
        env=os.environ,
        budget=budget,
    )
    assert (
        runner.cell_verdict(
            baseline,
            label="control",
            diagnostic=None,
            nonce=nonce,
            baseline_seconds=None,
            budget=budget,
        )
        == "green"
    )
    captured = []
    popen = subprocess.Popen

    def owned(*args, **kwargs):
        child = popen(*args, **kwargs)
        captured.append(child.pid)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", owned)
    # The descendant inherits stdout and keeps it open if only the leader is killed.
    code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print({marker!r},flush=True); time.sleep(60)"
    try:
        hung = runner.run_cell(
            [sys.executable, "-c", code], cwd=tmp_path, env=os.environ, budget=budget
        )
        assert hung["timed_out"] and hung["duration_seconds"] < budget + 2
        assert (
            runner.cell_verdict(
                hung,
                label="uninterruptible-backoff",
                diagnostic="shutdown delayed",
                nonce=nonce,
                baseline_seconds=baseline["duration_seconds"],
                budget=budget,
            )
            == "killed by timeout"
        )
        with pytest.raises(AssertionError, match="non-hang cell timed out"):
            runner.cell_verdict(
                hung,
                label="deadline-disabled",
                diagnostic="deadline",
                nonce=nonce,
                baseline_seconds=baseline["duration_seconds"],
                budget=budget,
            )
        with pytest.raises(AssertionError, match="non-hang cell timed out"):
            runner.cell_verdict(
                hung,
                label="control",
                diagnostic=None,
                nonce=nonce,
                baseline_seconds=None,
                budget=budget,
            )
        for slow in (None, budget * 0.75):
            with pytest.raises(AssertionError, match="missing or slow baseline"):
                runner.cell_verdict(
                    hung,
                    label="uninterruptible-backoff",
                    diagnostic="shutdown delayed",
                    nonce=nonce,
                    baseline_seconds=slow,
                    budget=budget,
                )
        slow_control = {**baseline, "duration_seconds": budget * 0.75}
        with pytest.raises(AssertionError, match="control not well inside"):
            runner.cell_verdict(
                slow_control,
                label="control",
                diagnostic=None,
                nonce=nonce,
                baseline_seconds=None,
                budget=budget,
            )
        print(
            f"forced-timeout: baseline_seconds={baseline['duration_seconds']:.6f} mutant_seconds={hung['duration_seconds']:.6f} budget_seconds={budget} verdict=killed-by-timeout"
        )
    finally:
        for pid in captured:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
