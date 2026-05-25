"""Stability test for the VRT1 test vectors.

Reruns the generator and asserts the output JSON files are
byte-identical to the checked-in vectors. If this test fails, either:

  (a) A legitimate protocol change was made — bump the spec version,
      regenerate the vectors, commit both together.
  (b) The reference implementation drifted from the spec — investigate
      and fix the implementation, NOT the vectors.

Either way, no silent protocol drift gets past CI.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


VECTORS_DIR = Path(__file__).resolve().parents[1] / "test-vectors"


def _regenerate_in_tmpdir(tmp_path: Path) -> Path:
    """Run the generator with VECTORS_DIR pointed at a temp dir.

    Returns the temp dir so the caller can compare files.
    """
    # The generator writes to `<repo>/test-vectors/`. We can't easily
    # redirect it without modifying the script, so instead we generate
    # in-place and capture a snapshot, then compare to the pristine
    # checked-in copies (which we also snapshot first).
    raise NotImplementedError("see _stable_vectors_after_regen instead")


def _stable_vectors_after_regen() -> dict[str, str]:
    """Re-run the generator IN PLACE and return {filename: contents}
    for each vector file. The generator is deterministic (fixed
    privkeys + fixed aux_rand) so this is safe to do in CI.

    Deletes existing vectors first so that a partial generator failure
    cannot produce false passes (missing files surface as inventory
    mismatches rather than silently matching the old copies).
    """
    for p in VECTORS_DIR.glob("*.json"):
        p.unlink()
    result = subprocess.run(
        [sys.executable, "-m", "tests.generate_vectors"],
        capture_output=True, text=True, cwd=VECTORS_DIR.parent,
    )
    assert result.returncode == 0, (
        f"generate_vectors exited {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return {
        p.name: p.read_text()
        for p in sorted(VECTORS_DIR.glob("*.json"))
    }


def test_all_vectors_exist():
    """The 7 vector files declared in spec/VRT1.md Section 13 must exist."""
    expected = {
        "attestation.json",
        "merkle.json",
        "op_return.json",
        "nostr_attestation_event.json",
        "nostr_checkpoint_event.json",
        "agent_action.json",
        "kwh_measurement.json",
    }
    actual = {p.name for p in VECTORS_DIR.glob("*.json")}
    assert actual == expected, (
        f"vector inventory drift — missing: {expected - actual}, "
        f"unexpected: {actual - expected}"
    )


def test_vectors_are_byte_stable():
    """Regenerated vectors must match the checked-in copies byte-for-byte."""
    # Snapshot the checked-in copies BEFORE regeneration.
    before = {
        p.name: p.read_text()
        for p in sorted(VECTORS_DIR.glob("*.json"))
    }
    after = _stable_vectors_after_regen()
    assert set(before.keys()) == set(after.keys()), (
        "file inventory changed during regeneration"
    )
    for name in sorted(before):
        assert before[name] == after[name], (
            f"vector drift in {name}: "
            "either the reference implementation changed wire format, "
            "or a legitimate protocol change wasn't accompanied by a "
            "vector regeneration + commit."
        )


def test_every_vector_is_valid_json():
    """Sanity: every file under test-vectors/ MUST parse as JSON."""
    for p in VECTORS_DIR.glob("*.json"):
        try:
            json.loads(p.read_text())
        except json.JSONDecodeError as e:
            pytest.fail(f"{p.name}: {e}")


def test_every_vector_declares_a_spec_section():
    """Every vector file MUST reference the spec section it covers, so
    a reader can jump from a vector to the prose that describes it."""
    for p in VECTORS_DIR.glob("*.json"):
        data = json.loads(p.read_text())
        assert "spec_section" in data, (
            f"{p.name} missing 'spec_section' field"
        )
        assert data["spec_section"], f"{p.name} has empty 'spec_section'"
