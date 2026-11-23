"""Actual native DSP product-use receipt contract and public CLI smoke."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from dsp.runner.user_activity_observation import (
    ObservationError, record_cli_run, validation_counts,
)


def test_private_local_minimal_observation_does_not_copy_secrets(tmp_path: Path):
    secret = "MY_API_TOKEN_NEVER_LEAK_98765"
    (tmp_path / "validation.json").write_text(json.dumps({
        "results": [
            {"scenario_id": "dummy", "decision": "success", "evidence": {
                "target": "192.0.2.1", "credential": secret,
            }},
            {"scenario_id": "other", "decision": "failure",
             "raw_message": secret},
        ]
    }), encoding="utf-8")
    path = record_cli_run(
        tmp_path, run_id="20261123_test", exit_code=2,
        dry_run=True, execution_provider="local", scenario_count=2,
    )
    data = json.loads(path.read_text())
    body = path.read_text()
    assert secret not in body and "192.0.2.1" not in body
    assert data["schema"] == "dsp.user-activity-observation.v1"
    assert data["validation_decision_counts"] == {"failure": 1, "success": 1}
    assert data["run_outcome"] == "NONZERO_EXIT"
    assert data["real_external_effect"] == "NOT_PERFORMED"
    assert data["full_user_e2e_gate"] == "NOT_ESTABLISHED"
    assert data["release_authority"] == "NO"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert data["source_git_head"] is None or len(data["source_git_head"]) == 40
    assert all(k not in data for k in ("target_net", "credential", "raw_command"))


def test_symlink_or_invalid_input_rejects(tmp_path: Path):
    path = tmp_path / "alias"
    path.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ObservationError, match="DIRECTORY_INVALID"):
        record_cli_run(
            path, run_id="test", exit_code=0, dry_run=True,
            execution_provider="local", scenario_count=1,
        )
    with pytest.raises(ObservationError, match="INPUT_INVALID"):
        record_cli_run(
            tmp_path, run_id="../unsafe", exit_code=0, dry_run=True,
            execution_provider="local", scenario_count=1,
        )
    with pytest.raises(ObservationError, match="INPUT_INVALID"):
        record_cli_run(
            tmp_path, run_id="valid", exit_code=True, dry_run=True,
            execution_provider="local", scenario_count=1,
        )


def test_unreadable_oversized_or_bad_validation_keeps_unverified(tmp_path: Path):
    (tmp_path / "validation.json").write_text(
        json.dumps({"results": [{"decision": "success", "token": "SECRET"}]})
    )
    count, ok = validation_counts(tmp_path)
    assert ok and count == {"success": 1}
    (tmp_path / "validation.json").write_bytes(b"z" * (512 * 1024 + 1))
    count, ok = validation_counts(tmp_path)
    assert not ok and not count
    path = record_cli_run(
        tmp_path, run_id="test", exit_code=0, dry_run=False,
        execution_provider="webshell", scenario_count=1,
    )
    d = json.loads(path.read_text())
    assert d["validation_artifact_read"] is False
    assert d["real_external_effect"] == "NOT_INDEPENDENTLY_ATTESTED"
    assert d["full_user_e2e_gate"] == "NOT_ESTABLISHED"


def test_public_cli_dummy_dry_run_automatically_creates_receipt(tmp_path: Path):
    # This is a genuine public CLI run, not an in-memory mock or fake ledger.
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    # Another product test may set DSP_RUNS_DIR process-globally without
    # restoring it; a real CLI user scenario must isolate its run root.
    env.pop("DSP_RUNS_DIR", None)
    env["PYTHONPATH"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    p = subprocess.run(
        [
            sys.executable, "-B", "-m", "dsp.runner.cli",
            "run", "--scenarios", "dummy", "--profile", "low",
            "--target-net", "192.0.2.0/24",
            "--dry-run", "--max-hosts", "2", "--quiet",
        ],
        cwd=root, env=env, capture_output=True, text=True, timeout=45,
    )
    assert p.returncode == 0, (p.stdout[-1500:], p.stderr[-1000:])
    run_dirs = list((tmp_path / ".dsp" / "runs").glob("*"))
    assert len(run_dirs) == 1, run_dirs
    d = run_dirs[0]
    obs = d / "user_activity_observation.json"
    assert obs.is_file(), list(d.iterdir())
    report = json.loads(obs.read_text())
    assert report["run_exit_code"] == 0
    assert report["dry_run"] is True and report["scenario_count"] == 1
    assert report["validation_decision_counts"].get("success") == 1
    assert all(report["artifact_presence"].values())
    assert report["source_git_head"] is not None
    assert report["full_user_e2e_gate"] == "NOT_ESTABLISHED"
    assert "192.0.2.0" not in obs.read_text()
