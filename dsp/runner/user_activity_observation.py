"""Minimal, local product-use receipt for every completed public DSP CLI run.

This is not user-identity attestation, a Full User E2E PASS or release authority.
No target IP/CIDR, endpoint, credential, event payload or raw command is stored.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from dsp import __version__

SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
MAX_VALIDATION_BYTES = 512 * 1024
VERSION_RE = re.compile(r"^[0-9a-f]{40}$")


class ObservationError(ValueError):
    pass


def source_identity() -> tuple[str | None, str]:
    """Report only a pinned exact checkout HEAD; installed wheels stay UNKNOWN."""
    root = Path(__file__).resolve().parents[2]
    try:
        p = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True, capture_output=True, timeout=3,
        )
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            text=True, capture_output=True, timeout=3,
        )
        if (
            p.returncode == 0
            and top.returncode == 0
            and Path(top.stdout.strip()).resolve() == root
            and VERSION_RE.fullmatch(p.stdout.strip())
        ):
            return p.stdout.strip(), "GIT_HEAD_OBSERVED"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return None, "SOURCE_UNVERIFIED"


def validation_counts(run_dir: Path) -> tuple[dict[str, int], bool]:
    path = run_dir / "validation.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_VALIDATION_BYTES:
            return {}, False
        source = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {}, False
    rows = source.get("results") if isinstance(source, dict) else None
    if not isinstance(rows, list):
        return {}, False
    counts: Counter[str] = Counter()
    for row in rows:
        if not isinstance(row, dict):
            return {}, False
        name = row.get("decision")
        if name not in {"success", "failure", "partial", "blocked"}:
            name = "unknown"
        counts[str(name)] += 1
    return dict(sorted(counts.items())), True


def record_cli_run(
    run_dir: Path, *, run_id: str, exit_code: int, dry_run: bool,
    execution_provider: str, scenario_count: int,
) -> Path:
    if (
        not SAFE_RUN_ID.fullmatch(run_id)
        or type(exit_code) is not int or exit_code < 0 or exit_code > 255
        or type(dry_run) is not bool
        or execution_provider not in {"local", "webshell"}
        or type(scenario_count) is not int or not 0 <= scenario_count <= 10000
    ):
        raise ObservationError("OBSERVATION_INPUT_INVALID")
    if not run_dir.is_dir() or run_dir.is_symlink():
        raise ObservationError("OBSERVATION_DIRECTORY_INVALID")
    head, provenance = source_identity()
    counts, validation_readback = validation_counts(run_dir)
    status = "NONZERO_EXIT" if exit_code else "RUN_COMPLETED"
    receipt = {
        "schema": "dsp.user-activity-observation.v1",
        "kind": "native-cli-observation",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "product_version": __version__,
        "source_git_head": head,
        "source_identity": provenance,
        "execution_provider": execution_provider,
        "scenario_count": scenario_count,
        "dry_run": dry_run,
        "run_exit_code": exit_code,
        "run_outcome": status,
        "validation_decision_counts": counts,
        "validation_artifact_read": validation_readback,
        "artifact_presence": {
            name: (run_dir / name).is_file() and not (run_dir / name).is_symlink()
            for name in ("run.json", "validation.json", "report.json", "report.md", "events.jsonl")
        },
        "real_external_effect": "NOT_PERFORMED" if dry_run else "NOT_INDEPENDENTLY_ATTESTED",
        "full_user_e2e_gate": "NOT_ESTABLISHED",
        "independent_auditor": "NOT_ATTESTED",
        "release_authority": "NO",
    }
    target = run_dir / "user_activity_observation.json"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=run_dir, prefix=".user_activity_observation.",
            suffix=".tmp", encoding="utf-8", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
    except OSError as exc:
        raise ObservationError("OBSERVATION_WRITE_FAILED") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target
