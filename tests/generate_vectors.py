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


def gen_key_registry_snapshot() -> None:
    """Section 8.5 - chained key registry snapshots, plus negatives.

    The chain is a key ROTATION AUTHORIZATION chain, not merely a history:
    the agent key that signs a snapshot appears in that snapshot's own
    registry, and a successor must be signed by a key its parent already
    lists. So the vectors show a handover - snapshot 2 introduces agent
    key B and is signed by agent key A, which snapshot 1 vouches for.

    Negatives ship as literal canonical bytes plus the action_id they
    produce, because a negative described as a mutation procedure tests
    the reader's reconstruction rather than the rule. The last negative
    is the exception that proves the rule's shape: it carries a valid
    signature and is rejected only by its context.
    """
    import copy
    import hashlib

    from veritas.crypto import schnorr_sign, tagged_hash
    from vrt1_agents.action import (
        ACTION_TAG, SignedAction, action_digest, action_id, canonical_json,
    )

    key_a = OracleKey.from_hex(AGENT_A_PRIVKEY_HEX)
    key_b = OracleKey.from_hex(AGENT_B_PRIVKEY_HEX)

    def synthetic_pubkey(label: str) -> str:
        """Deterministic placeholder. Not key material for any operator."""
        return hashlib.sha256(label.encode()).hexdigest()[:40]

    # The signing key lives in the registry it publishes, or the registry
    # authenticates every key except the one that authenticated the registry.
    agent_a = {
        "key_id": "vrt1-agent-a",
        "key_type": "secp256k1_xonly",
        "public_key": key_a.xonly_pubkey_hex,
        "custody": "offline",
        "revoked": False,
        "valid_from": 1_690_000_000,
        "valid_until": None,
    }
    agent_b = {
        "key_id": "vrt1-agent-b",
        "key_type": "secp256k1_xonly",
        "public_key": key_b.xonly_pubkey_hex,
        "custody": "hsm",
        "revoked": False,
        "valid_from": 1_709_000_000,
        "valid_until": None,
    }
    k_old = {
        "key_id": "signer-2023-07",
        "key_type": "eth_address",
        "public_key": synthetic_pubkey("vrt1-example-signer-2023-07"),
        "custody": "hot_process",
        "revoked": False,
        "valid_from": 1_690_000_000,
        "valid_until": 1_705_000_000,
    }
    k_mid = {
        "key_id": "signer-2023-10",
        "key_type": "eth_address",
        "public_key": synthetic_pubkey("vrt1-example-signer-2023-10"),
        "custody": "hot_process",
        "revoked": False,
        "valid_from": 1_698_000_000,
        "valid_until": None,
    }

    def snapshot(keys: list[dict], ts: int, agent: OracleKey, parent: str | None):
        return make_action(
            agent_pubkey_hex=agent.xonly_pubkey_hex,
            action_type="key_registry_snapshot",
            target="example.attester/key-registry",
            params={"snapshot": {"keys": keys, "schema_version": 1, "ts": ts}},
            outcome={
                "active_count": sum(1 for k in keys if not k["revoked"]),
                "revoked_count": sum(1 for k in keys if k["revoked"]),
            },
            ts=ts,
            parent_action=parent,
        )

    def signed_vector(action, agent: OracleKey, note: str) -> dict:
        sig = schnorr_sign(action_digest(action), agent, aux_rand=FIXED_AUX_RAND)
        signed = SignedAction(action=action, sig=sig.hex())
        assert signed.verify()
        return {
            "note": note,
            "action": action.to_payload(),
            "canonical_bytes_hex": action.canonical_bytes().hex(),
            "canonical_bytes_len": len(action.canonical_bytes()),
            "action_id_hex": action_id(action),
            "sig_hex": signed.sig,
            "signed_by_key_id": next(
                k["key_id"] for k in action.params["snapshot"]["keys"]
                if k["public_key"] == action.agent
            ) if any(k["public_key"] == action.agent
                     for k in action.params["snapshot"]["keys"]) else None,
            "verify_result_expected": True,
        }

    # Registries render newest-first, so array order is not sorted order.
    genesis = snapshot([agent_a, k_mid, k_old], 1_700_000_000, key_a, None)
    assert "parent_action" not in genesis.to_payload()
    v_genesis = signed_vector(
        genesis, key_a,
        "Genesis. parent_action is omitted, never serialized as null (8.1). The signing "
        "key is listed in the registry it publishes. Genesis is not authorized by a "
        "parent: its trust root is the anchor plus an out-of-band binding of the agent "
        "pubkey to the operator, and that first hop is not cryptographic.",
    )

    # Handover: B is introduced, A still signs. A is what the parent vouches for.
    agent_a_handover = dict(agent_a, valid_until=1_712_000_000)
    successor_keys = [agent_b, agent_a_handover, k_mid, dict(k_old, revoked=True)]
    successor = snapshot(successor_keys, 1_710_000_000, key_a, v_genesis["action_id_hex"])
    v_successor = signed_vector(
        successor, key_a,
        "Authorized successor: introduces agent key B and revokes an attester key, signed "
        "by agent key A, which the parent lists unrevoked with a window containing this "
        "ts. The outgoing key authorizes its replacement.",
    )

    base = genesis.to_payload()

    def negative(case: str, rule: str, mutate) -> dict:
        payload = copy.deepcopy(base)
        mutate(payload)
        raw = canonical_json(payload)
        return {
            "case": case,
            "rule_violated": rule,
            "canonical_bytes_hex": raw.hex(),
            "canonical_bytes_len": len(raw),
            "action_id_hex": tagged_hash(ACTION_TAG, raw).hex(),
            "verify_expected": False,
        }

    def raw_hex(p):
        entry = p["params"]["snapshot"]["keys"][2]
        entry["public_key"] = "0x" + entry["public_key"].upper()

    def ts_as_string(p):
        p["params"]["snapshot"]["ts"] = str(p["params"]["snapshot"]["ts"])

    def drop_null_valid_until(p):
        del p["params"]["snapshot"]["keys"][0]["valid_until"]

    def sort_the_array(p):
        snap = p["params"]["snapshot"]
        snap["keys"] = sorted(snap["keys"], key=lambda k: k["key_id"])

    def wrong_count(p):
        p["outcome"]["active_count"] = 4

    def snapshot_from_the_future(p):
        p["params"]["snapshot"]["ts"] = p["ts"] + 1

    negatives = [
        negative("public_key carried 0x-prefixed and upper-case",
                 "1.5 / hex normalization", raw_hex),
        negative("snapshot.ts as a decimal string instead of an integer",
                 "8.5 timestamps are integer Unix seconds", ts_as_string),
        negative("open-ended valid_until omitted instead of serialized as null",
                 "8.5 null valid_until MUST be serialized", drop_null_valid_until),
        negative("keys[] sorted by key_id instead of preserved in record order",
                 "1.4 canonical JSON sorts object keys, never arrays", sort_the_array),
        negative("outcome.active_count says 4 where keys[] holds 3 unrevoked entries",
                 "8.5 counts MUST equal the partition of keys[] on revoked", wrong_count),
        negative("snapshot.ts later than the action ts: a registry read from the future",
                 "8.5 snapshot.ts MUST NOT be later than ts", snapshot_from_the_future),
    ]

    # The one negative that is valid in isolation and invalid in context: a successor
    # signed by a key its parent never vouched for. Signature verifies; chain refuses it.
    usurper = snapshot(successor_keys, 1_710_000_000, key_b, v_genesis["action_id_hex"])
    usurper_sig = schnorr_sign(action_digest(usurper), key_b, aux_rand=FIXED_AUX_RAND)
    assert SignedAction(action=usurper, sig=usurper_sig.hex()).verify()
    assert not any(k["public_key"] == key_b.xonly_pubkey_hex
                   for k in genesis.params["snapshot"]["keys"])
    unauthorized = {
        "case": "successor signed by agent key B, which the parent snapshot does not list",
        "rule_violated": "8.5 a successor MUST be signed by a key its parent lists "
                         "unrevoked and in-window",
        "canonical_bytes_hex": usurper.canonical_bytes().hex(),
        "canonical_bytes_len": len(usurper.canonical_bytes()),
        "action_id_hex": action_id(usurper),
        "sig_hex": usurper_sig.hex(),
        "own_signature_verifies": True,
        "verify_expected": False,
        "note": "This vector is the reason the rule is worth stating. Every other "
                "negative here fails at the digest. This one hashes correctly, carries a "
                "signature that verifies against its own agent field, and is refused "
                "only because its parent never authorized the signer. An implementation "
                "that verifies records one at a time will accept it.",
    }

    canonical_ids = {v_genesis["action_id_hex"], v_successor["action_id_hex"]}
    ids = [n["action_id_hex"] for n in negatives] + [unauthorized["action_id_hex"]]
    assert not canonical_ids & set(ids), "a negative collides with a positive"
    assert len(set(ids)) == len(ids), "two negatives produce the same action_id"

    _write("key_registry_snapshot.json", {
        "spec_section": "8.5",
        "action_type": "key_registry_snapshot",
        "description": "Chained key registry snapshots with a signing-key handover. "
                       "Reproducible from AGENT_A/AGENT_B_PRIVKEY + fixed timestamps + "
                       "fixed aux_rand.",
        "agent_a_privkey_hex_demo_only": AGENT_A_PRIVKEY_HEX,
        "agent_b_privkey_hex_demo_only": AGENT_B_PRIVKEY_HEX,
        "agent_a_pubkey_xonly_hex": key_a.xonly_pubkey_hex,
        "agent_b_pubkey_xonly_hex": key_b.xonly_pubkey_hex,
        "eth_public_keys_are_synthetic": "sha256-derived placeholders, not key material "
                                         "for any real operator",
        "custody_vocabulary": ["hot_process", "kms", "hsm", "offline",
                               "air_gapped", "unknown"],
        "custody_is_unordered": "VRT1 supplies the vocabulary so custody is comparable "
                                "across attesters. It does not rank the values, does not "
                                "endorse any of them, and does not treat 'unknown' as a "
                                "failure.",
        "how_to_use_negatives": "Each negative is a literal input. Hash "
                                "canonical_bytes_hex with tagged_hash('VRT1/agent-action', "
                                "bytes), confirm you get action_id_hex, then confirm your "
                                "verifier rejects it. Do not regenerate the mutation.",
        "positives": [v_genesis, v_successor],
        "negatives": negatives,
        "chain_negatives": [unauthorized],
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
    gen_key_registry_snapshot()
    gen_kwh_measurement()
    print(f"wrote {len(list(_vectors_dir().glob('*.json')))} vectors to "
          f"{_vectors_dir()}")


if __name__ == "__main__":
    main()
