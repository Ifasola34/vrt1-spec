"""Generate canonical test vectors for the VRT1 spec.

The vectors are produced from seeded inputs so regeneration is
byte-identical across machines. Implementations of VRT1 should be
able to reproduce these bytes; the stability test
(`tests/test_vectors_stable.py`) reruns this generator and asserts
the output matches the checked-in JSON.

Run with:
    python -m tests.generate_vectors

Outputs under `test-vectors/`:
    attestation.json
    merkle.json
    op_return.json
    nostr_attestation_event.json
    nostr_checkpoint_event.json
    agent_action.json
    kwh_measurement.json
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from veritas.anchor import (
    build_op_return_payload,
    parse_op_return_payload,
)
from veritas.attestation import (
    Attestation,
    SignedAttestation,
    attestation_digest,
    make_attestation,
    sign_attestation,
)
from veritas.crypto import OracleKey, tagged_hash
from veritas.merkle import MerkleTree, verify_merkle_proof
from veritas.nostr import (
    build_attestation_event,
    build_checkpoint_event,
)

# Imports from satellites
from vrt1_agents.action import make_action, sign_action
from vrt1_agents.nostr import build_action_event
from vrt1_kwh.attestation import make_measurement, sign_measurement
from vrt1_kwh.measurer import MeasurementSample


# ---------- deterministic seeds ------------------------------------
# Fixed 32-byte privkeys so vectors are byte-identical across runs.
# These keys are PUBLIC AND DEMO-ONLY — never use them in production.

ORACLE_PRIVKEY_HEX = (
    "1111111111111111111111111111111111111111111111111111111111111111"
)
AGENT_A_PRIVKEY_HEX = (
    "2222222222222222222222222222222222222222222222222222222222222222"
)
AGENT_B_PRIVKEY_HEX = (
    "3333333333333333333333333333333333333333333333333333333333333333"
)
DEVICE_PRIVKEY_HEX = (
    "4444444444444444444444444444444444444444444444444444444444444444"
)

FIXED_TS = 1_700_000_000
FIXED_EPOCH = 7
# BIP-340 aux_rand bytes — fixed for deterministic signatures.
FIXED_AUX_RAND = bytes(32)   # 32 zero bytes


# ---------- helpers ------------------------------------------------


def _vectors_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "test-vectors"


def _write(name: str, obj: dict) -> None:
    out = _vectors_dir() / name
    out.parent.mkdir(parents=True, exist_ok=True)
    # Pretty-print so the JSON is human-reviewable in PRs while still
    # being parseable for byte-comparison stability tests.
    out.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _deterministic_sign_attestation(att: Attestation, key: OracleKey) -> SignedAttestation:
    """Wrap sign_attestation with fixed aux_rand so the resulting
    signature is byte-identical across runs.

    WARNING: this bypasses sign_attestation() and calls schnorr_sign
    directly. If sign_attestation ever changes its internal signing
    flow (e.g. adds nonce derivation or pre-hashing), this helper
    will diverge and the stability test will correctly fail — but the
    root cause will be here, not in the reference implementation.
    The same applies to gen_agent_action and gen_kwh_measurement below.
    """
    from veritas.crypto import schnorr_sign
    if att.oracle != key.xonly_pubkey_hex:
        raise ValueError("attestation.oracle does not match key")
    sig = schnorr_sign(attestation_digest(att), key, aux_rand=FIXED_AUX_RAND)
    return SignedAttestation(attestation=att, sig=sig.hex())


# ---------- generators ---------------------------------------------


def gen_attestation() -> SignedAttestation:
    """Section 3 — inference attestation."""
    key = OracleKey.from_hex(ORACLE_PRIVKEY_HEX)
    att = make_attestation(
        model="veritas.sentiment.keyword.v1",
        input_hash="ab" * 32,
        output={"label": "bullish", "score": 0.42},
        epoch=FIXED_EPOCH,
        oracle_pubkey_hex=key.xonly_pubkey_hex,
        ts=FIXED_TS,
    )
    signed = _deterministic_sign_attestation(att, key)
    _write("attestation.json", {
        "spec_section": "3",
        "description": "Canonical signed attestation. Reproducible from "
                       "ORACLE_PRIVKEY + fixed ts + fixed aux_rand.",
        "oracle_privkey_hex_demo_only": ORACLE_PRIVKEY_HEX,
        "oracle_pubkey_xonly_hex": key.xonly_pubkey_hex,
        "attestation": signed.attestation.to_payload(),
        "canonical_bytes_hex": signed.attestation.canonical_bytes().hex(),
        "attestation_digest_hex": attestation_digest(signed.attestation).hex(),
        "sig_hex": signed.sig,
        "verify_result_expected": True,
    })
    return signed


def gen_merkle() -> None:
    """Section 4 — Merkle trees of various sizes with proofs."""
    import hashlib
    def leaf(i: int) -> bytes:
        return hashlib.sha256(i.to_bytes(4, "big")).digest()

    samples = {}
    for n in [1, 2, 3, 4, 5, 7, 8]:
        leaves = [leaf(i) for i in range(n)]
        tree = MerkleTree(leaves)
        proofs = []
        for i in range(n):
            p = tree.prove(i)
            proofs.append({
                "index": p.index,
                "leaf_hex": p.leaf.hex(),
                "siblings_hex": [s.hex() for s in p.siblings],
                "directions": p.directions,
                "verify_expected": True,
            })
            assert verify_merkle_proof(p), f"sanity: proof n={n} i={i}"
        samples[str(n)] = {
            "size": n,
            "root_hex": tree.root.hex(),
            "leaves_hex": [l.hex() for l in leaves],
            "proofs": proofs,
        }
    _write("merkle.json", {
        "spec_section": "4",
        "description": "Merkle trees of size 1, 2, 3, 4, 5, 7, 8 with "
                       "inclusion proofs for every leaf. Leaves are "
                       "SHA-256 of the 4-byte big-endian index. "
                       "Construction uses RFC-6962 0x00/0x01 prefixes "
                       "with Bitcoin-style odd-leaf duplication.",
        "trees": samples,
    })


def gen_op_return() -> None:
    """Section 5 — OP_RETURN 49-byte payload."""
    root = bytes.fromhex("cd" * 32)
    epoch = FIXED_EPOCH
    leaf_count = 5
    payload = build_op_return_payload(
        merkle_root=root, epoch=epoch, leaf_count=leaf_count,
    )
    parsed = parse_op_return_payload(payload)
    _write("op_return.json", {
        "spec_section": "5",
        "description": "OP_RETURN payload roundtrip (49 bytes).",
        "input": {
            "merkle_root_hex": root.hex(),
            "epoch": epoch,
            "leaf_count": leaf_count,
        },
        "payload_hex": payload.hex(),
        "payload_length_bytes": len(payload),
        "parsed": {
            "tag": parsed["tag"],
            "version": parsed["version"],
            "epoch": parsed["epoch"],
            "leaf_count": parsed["leaf_count"],
            "merkle_root_hex": parsed["merkle_root"].hex(),
        },
    })


def gen_nostr_attestation_event(signed: SignedAttestation) -> None:
    """Section 7 — Nostr kind-30078 attestation event."""
    key = OracleKey.from_hex(ORACLE_PRIVKEY_HEX)
    from veritas.nostr import (
        KIND_VERITAS_ATTESTATION,
        NostrEvent,
    )
    from veritas.attestation import canonical_json

    # Build the event manually so we can fix aux_rand for deterministic sig.
    att = signed.attestation
    tags = [
        ["d", f"{att.epoch}:{0}"],
        ["model", att.model],
        ["v", f"VRT1.{att.v}"],
        ["epoch", str(att.epoch)],
        ["input", att.input_hash],
    ]
    content = base64.b64encode(canonical_json(
        {"attestation": att.to_payload(), "sig": signed.sig}
    )).decode("ascii")
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=att.ts,
        kind=KIND_VERITAS_ATTESTATION,
        tags=tags,
        content=content,
    )
    evt.id = evt.compute_id()
    from veritas.crypto import schnorr_sign
    evt.sig = schnorr_sign(
        bytes.fromhex(evt.id), key, aux_rand=FIXED_AUX_RAND,
    ).hex()

    _write("nostr_attestation_event.json", {
        "spec_section": "7",
        "description": "Kind-30078 Nostr attestation event derived from "
                       "the canonical attestation. Re-uses ORACLE_PRIVKEY.",
        "event": evt.to_dict(),
        "serialize_for_id_bytes_hex": evt.serialize_for_id().hex(),
        "verify_event_id_expected": True,
        "verify_signature_expected": True,
    })


def gen_nostr_checkpoint_event() -> None:
    """Section 6 — Nostr kind-30079 checkpoint event."""
    key = OracleKey.from_hex(ORACLE_PRIVKEY_HEX)
    from veritas.nostr import KIND_VERITAS_CHECKPOINT, NostrEvent
    from veritas.attestation import canonical_json
    payload = {
        "epoch": FIXED_EPOCH,
        "root": "cd" * 32,
        "count": 5,
        "anchor_txid": "ab" * 32,
    }
    tags = [
        ["d", f"checkpoint:{FIXED_EPOCH}"],
        ["v", "VRT1.1"],
        ["root", "cd" * 32],
        ["anchor", "ab" * 32],
    ]
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=FIXED_TS + 60,
        kind=KIND_VERITAS_CHECKPOINT,
        tags=tags,
        content=canonical_json(payload).decode("utf-8"),
    )
    evt.id = evt.compute_id()
    from veritas.crypto import schnorr_sign
    evt.sig = schnorr_sign(
        bytes.fromhex(evt.id), key, aux_rand=FIXED_AUX_RAND,
    ).hex()
    _write("nostr_checkpoint_event.json", {
        "spec_section": "6",
        "description": "Kind-30079 checkpoint event committing to "
                       "epoch + root + count + anchor_txid in its "
                       "signed content.",
        "event": evt.to_dict(),
        "content_parsed": payload,
        "verify_event_id_expected": True,
        "verify_signature_expected": True,
    })


def gen_agent_action() -> None:
    """Section 8 — kind-1990 agent action."""
    from veritas.crypto import schnorr_sign
    from vrt1_agents.action import (
        SignedAction, action_digest, action_id,
    )
    key = OracleKey.from_hex(AGENT_A_PRIVKEY_HEX)
    action = make_action(
        agent_pubkey_hex=key.xonly_pubkey_hex,
        action_type="review",
        target="https://news.example/article-42",
        outcome={"verdict": "trustworthy", "score": 4},
        ts=FIXED_TS,
    )
    sig = schnorr_sign(action_digest(action), key, aux_rand=FIXED_AUX_RAND)
    signed = SignedAction(action=action, sig=sig.hex())
    _write("agent_action.json", {
        "spec_section": "8",
        "description": "Signed agent action (kind 1990). Reproducible "
                       "from AGENT_A_PRIVKEY + fixed ts + fixed aux_rand.",
        "agent_privkey_hex_demo_only": AGENT_A_PRIVKEY_HEX,
        "agent_pubkey_xonly_hex": key.xonly_pubkey_hex,
        "action": signed.action.to_payload(),
        "canonical_bytes_hex": action.canonical_bytes().hex(),
        "action_id_hex": action_id(action),
        "sig_hex": signed.sig,
        "verify_result_expected": True,
    })


def gen_kwh_measurement() -> None:
    """Section 9 — kind-1991 kWh measurement."""
    from veritas.crypto import schnorr_sign
    from vrt1_kwh.attestation import (
        SignedMeasurement, measurement_digest, measurement_id,
    )
    key = OracleKey.from_hex(DEVICE_PRIVKEY_HEX)
    sample = MeasurementSample(
        window_start=FIXED_TS,
        window_end=FIXED_TS + 60,
        kwh=0.000600000,
        source="stub",
        model_id="vrt1.kwh.stub.v1",
    )
    measurement = make_measurement(
        device_pubkey_hex=key.xonly_pubkey_hex, sample=sample,
    )
    sig = schnorr_sign(
        measurement_digest(measurement), key, aux_rand=FIXED_AUX_RAND,
    )
    signed = SignedMeasurement(measurement=measurement, sig=sig.hex())
    _write("kwh_measurement.json", {
        "spec_section": "9",
        "description": "Signed kWh measurement (kind 1991). 60s window "
                       "at ~10 µWh/s = 600 µWh = 0.0006 kWh.",
        "device_privkey_hex_demo_only": DEVICE_PRIVKEY_HEX,
        "device_pubkey_xonly_hex": key.xonly_pubkey_hex,
        "measurement": signed.measurement.to_payload(),
        "canonical_bytes_hex": measurement.canonical_bytes().hex(),
        "measurement_id_hex": measurement_id(measurement),
        "sig_hex": signed.sig,
        "verify_result_expected": True,
    })


# ---------- entry point --------------------------------------------


def main() -> None:
    signed = gen_attestation()
    gen_merkle()
    gen_op_return()
    gen_nostr_attestation_event(signed)
    gen_nostr_checkpoint_event()
    gen_agent_action()
    gen_kwh_measurement()
    print(f"wrote {len(list(_vectors_dir().glob('*.json')))} vectors to "
          f"{_vectors_dir()}")


if __name__ == "__main__":
    main()
