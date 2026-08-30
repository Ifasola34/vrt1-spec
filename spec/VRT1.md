# VRT1 — VERITAS Protocol Specification

| Field         | Value                                                  |
|---------------|--------------------------------------------------------|
| Version       | 1                                                      |
| Status        | Draft                                                  |
| Author        | Ifasola34                                              |
| License       | MIT                                                    |
| Reference impl| https://github.com/Ifasola34/veritas                   |
| Test vectors  | https://github.com/Ifasola34/vrt1-spec/tree/main/test-vectors |

---

## Abstract

VRT1 is a Bitcoin-anchored attestation protocol. An *oracle* signs
structured claims with a BIP-340 Schnorr key, batches them into a
Bitcoin-style Merkle tree once per epoch, commits the Merkle root to
Bitcoin via `OP_RETURN`, and publishes both the per-claim attestations
and the per-epoch checkpoint as NIP-01 Nostr events. Any third party
can independently verify that a given claim was signed by a specific
oracle, is included in a specific epoch's Merkle tree, and that the
tree's root is committed to a specific Bitcoin transaction — without
ever trusting the oracle's own infrastructure.

The protocol is designed to be **general** beyond AI inference
attestations: agent actions (Section 8) and energy-consumption
measurements (Section 9) are parallel attestation types, all anchored
through the same epoch + Merkle + OP_RETURN flow.

---

## 1. Notation and Conventions

### 1.1 Requirement Keywords

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL
NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in
[RFC 2119].

### 1.2 Byte and integer encoding

Unless otherwise specified:

- All byte strings are sequences of 8-bit octets.
- Hex strings use lowercase `0-9` and `a-f`. Implementations MUST
  produce lowercase output but MAY accept mixed case on input
  (see Section 1.5).
- Big-endian byte order is used for all multi-byte integers EXCEPT
  where Bitcoin convention requires little-endian (the `OP_RETURN`
  payload uses big-endian; the underlying Bitcoin transaction
  serialization itself follows BIP-141 / BIP-143 little-endian
  conventions).

### 1.3 Cryptographic primitives

VRT1 uses the following primitives, all over the secp256k1 curve:

- **SHA-256:** as defined in [FIPS-180-4].
- **HMAC-SHA-256:** as defined in [RFC 2104].
- **BIP-340 Schnorr signatures:** 64-byte signatures over a 32-byte
  message digest, as defined in [BIP-340]. All VRT1 signatures are
  produced and verified per BIP-340.
- **Tagged hash:** as defined in [BIP-340] Section "Design":

      H_tag(x) := SHA256(SHA256(tag) || SHA256(tag) || x)

  where `tag` is encoded as UTF-8 octets and `||` denotes
  concatenation. Tags used by this spec are listed in Section 2.4.
- **Bitcoin-style double SHA-256:**

      d(x) := SHA256(SHA256(x))

  used inside the Merkle tree construction (Section 4).

### 1.4 Canonical JSON

Where this spec refers to "canonical JSON encoding", the encoding
MUST be produced by:

1. Recursively sorting all object keys lexicographically (UTF-8
   codepoint order).
2. Serializing with no whitespace between tokens. Separators MUST be
   `,` between items and `:` between keys and values (i.e. the
   Python `json.dumps(..., sort_keys=True, separators=(",", ":"),
   ensure_ascii=False)` form).
3. Strings MUST NOT escape non-ASCII characters (the
   `ensure_ascii=False` form). Implementations that use libraries
   defaulting to ASCII escaping MUST override this.
4. Numbers MUST be encoded as integers when integer-valued; floats
   MUST follow ECMAScript JSON.stringify semantics (no trailing
   zeros, no leading `+` on exponent).

This canonical form is what gets hashed for digest computation. Two
implementations that produce different bytes for the same logical
object produce different digests and therefore different signatures —
canonical form is what makes signatures verifiable across implementations.

### 1.5 Hex normalization on input

When ingesting hex-encoded data from external sources (Nostr events,
config files, CLI arguments), implementations:

- **MUST** accept lowercase hex.
- **SHOULD** accept uppercase or mixed-case hex (matches Bitcoin
  convention).
- **MUST NOT** accept hex with whitespace, `0x` prefixes, or other
  non-`[0-9a-fA-F]` characters.

**Scope: normalization applies only to values already known to be
hex-encoded bytes.** Every other string in a canonical payload is
carried **byte-identical**, whatever it looks like. A value is a
candidate for normalization because its field is declared to hold
hex bytes, never because its contents happen to resemble hex.

This is stated as a default rather than as a pair of categories
deliberately. An implementation that enumerates what to normalize and
what to preserve has nothing to say the first time it meets a string
belonging to neither list, and a canonicalizer with nothing to say is
a canonicalizer that guesses. Two implementations then guess
differently and produce different digests for the same record, which
is the failure this section exists to prevent.

Normalizing is the special case and **MUST** be justified per field;
preserving is the default and needs no justification. Concretely, an
asset identifier such as
`eip155:1/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` carries a
mixed-case checksum, and an unresolved or vendor-scoped identifier such
as `unresolved:VVV@1` carries a symbol whose casing an implementation
cannot prove is redundant. Neither is a hex byte string, so neither is
touched, and no rule has to be extended when the next such format
appears.

---

## 2. Terminology

### 2.1 Oracle

An entity that produces signed VRT1 attestations. Identified by a
32-byte x-only secp256k1 public key (BIP-340 form). The same key MAY
be used as the oracle's Nostr identity (Section 7).

### 2.2 Epoch

A contiguous time window during which an oracle's attestations are
accumulated. At epoch close, all attestations in that epoch are
arranged into a Merkle tree (Section 4) and the root is committed to
Bitcoin (Section 5). Epochs are identified by a monotonically
increasing unsigned 64-bit integer per oracle (0 through 2^64 − 1).

An oracle MUST NOT close an epoch with zero attestations. An epoch
with no attestations has no Merkle tree, no checkpoint, and no anchor
transaction. Consumers that encounter a checkpoint with `count: 0`
MUST reject it.

An epoch number is a **batch label scoped to one oracle**, and consumers
**MUST NOT** read it as a timestamp. The reference implementation
derives it as `floor(ts / 600)`, which is a convention of that
implementation rather than a requirement of this specification; what
the specification requires is that the number increase monotonically
per oracle. Epoch numbers from different oracles are unrelated and
**MUST NOT** be compared. Where a record is anchored by an oracle other
than its author, the epoch in the OP_RETURN payload is the *anchoring*
oracle's, not the author's.

Time evidence comes from the Bitcoin block that contains the anchor,
not from the epoch, and it is an **upper bound**: the anchor proves the
record existed *before* that block. It says nothing about when the
record was created, and a record's own `ts` remains a self-assertion no
matter how many epochs enclose it.

### 2.3 Attestation

The signed object an oracle produces for one claim. See Section 3 for
the wire format.

### 2.4 Domain-separation tags

VRT1 uses the following tagged-hash domains. Different tags MUST be
used for different object types so signatures cannot be cross-confused.

| Tag string           | Used for                                  | Section |
|----------------------|-------------------------------------------|---------|
| `VRT1`               | Protocol marker (4 bytes in `OP_RETURN`)  | 5       |
| `VRT1/attestation`   | Inference-attestation digest              | 3       |
| `VRT1/agent-action`  | Agent-action digest                       | 8       |
| `VRT1/kwh`           | kWh-measurement digest                    | 9       |
| `VRT1/anchor-key`    | Subkey derivation for anchor signing      | 5.4     |

---

## 3. Attestation (Inference)

### 3.1 Schema

An *inference attestation* is a JSON object with the following fields:

| Field       | Type    | Required | Description                                  |
|-------------|---------|----------|----------------------------------------------|
| `model`     | string  | Yes      | Stable identifier of the inference model.    |
| `input_hash`| string  | Yes      | Lowercase hex SHA-256 of the canonical input. MUST be exactly 64 lowercase hex characters (`[0-9a-f]{64}`). |
| `output`    | any     | Yes      | JSON-serializable inference result. MUST NOT be `null`. An inference that produces no output SHOULD use an empty object `{}`. |
| `ts`        | integer | Yes      | Unix seconds when the attestation was produced. Verifiers SHOULD reject attestations where `ts` exceeds the current wall clock by more than 300 seconds. |
| `epoch`     | integer | Yes      | Epoch number. MUST be a non-negative integer that fits in an unsigned 64-bit integer (0 through 2^64 − 1). |
| `oracle`    | string  | Yes      | 64-char lowercase hex of oracle's x-only pubkey. MUST be exactly 64 lowercase hex characters. |
| `v`         | integer | Yes      | Protocol version. MUST be `1`.               |
| `nonce`     | string  | No       | Optional random hex for per-attestation unlinkability. |

Implementations:

- **MUST** include all required fields.
- **MUST** omit `nonce` from the payload when its value is the empty
  string (otherwise the digest of an "absent nonce" attestation
  differs across implementations). A nonce containing only
  whitespace is a valid non-empty nonce and MUST be included.
- **MUST NOT** include any fields not listed above when computing the
  digest. Future extension fields are reserved for protocol version
  `v` > 1 and require updating this specification.

### 3.2 Digest

The 32-byte signing digest is:

```
attestation_digest := tagged_hash("VRT1/attestation", canonical_json(payload))
```

See Section 1.4 for the canonical JSON rules.

### 3.3 Signature

The signature is the 64-byte BIP-340 Schnorr signature of
`attestation_digest` under the oracle's private key, where
`oracle == hex(xonly_pubkey)`:

```
sig := schnorr_sign(attestation_digest, oracle_privkey)
```

Implementations MUST verify that `attestation.oracle` matches the
signing key's x-only pubkey before signing — silently overwriting the
field is a security risk.

### 3.4 Wire format

A signed attestation is wrapped as:

```json
{
  "attestation": { … payload as in Section 3.1 … },
  "sig": "<128-char lowercase hex>"
}
```

See `test-vectors/attestation.json` for a known-good example.

---

## 4. Merkle Tree

### 4.1 Construction

VRT1 uses a Bitcoin-style Merkle tree with RFC-6962-inspired
domain-separation prefixes:

- Each leaf is a 32-byte attestation digest.
- Internal nodes are computed as
  `d(0x01 || left || right)` where `d` is double SHA-256.
- Leaves are wrapped with a `0x00` prefix BEFORE being inserted at
  level 0:  `level_0[i] := d(0x00 || leaf[i])`.
- Odd-leaf duplication: when a level has an odd number of nodes, the
  last node is duplicated to produce an even number. This MUST be
  done at every internal level, not just the leaf level.

The prefix bytes prevent the second-preimage attack class CVE-2012-2459
identified for vanilla Bitcoin Merkle trees, in which a 32-byte
internal node hash could be reinterpreted as a leaf and vice-versa.

### 4.2 Inclusion proof

A Merkle inclusion proof for leaf at index `i` in a tree of size `N`
consists of:

| Field        | Type           | Description                          |
|--------------|----------------|--------------------------------------|
| `leaf`       | 32 bytes (hex) | The raw leaf digest (pre-prefix).    |
| `siblings`   | list of hex    | One 32-byte sibling per tree level.  |
| `directions` | list of int    | Per level: `0` = sibling on right, `1` = sibling on left. |
| `root`       | 32 bytes (hex) | The claimed Merkle root.             |
| `size`       | integer        | Total leaves `N` in the tree.        |
| `index`      | integer        | Position `i` of the leaf in the tree. |

For a tree of size 1, the proof has no siblings
(`siblings=[], directions=[]`). The root is `d(0x00 || leaf)` and
no further hashing is required.

### 4.3 Verification

To verify an inclusion proof, an implementation MUST:

1. Reject if `size <= 0`.
2. Reject if `not (0 <= index < size)`.
3. Reject if `len(leaf) != 32`.
4. Reject if `len(siblings) != len(directions)`.
5. Reject if `len(siblings)` differs from the expected depth for the
   given `size` (where depth is computed by repeatedly rounding `n`
   up to the next even number and halving until 1 remains).
6. Reject if the per-level `directions` do not match the bit-pattern
   derived from `index` and `size` at each level (defends against
   directional substitution).
7. Compute `cur := d(0x00 || leaf)`.
8. For each `(sibling, direction)` pair:
   - If `direction == 0`: `cur := d(0x01 || cur || sibling)`.
   - If `direction == 1`: `cur := d(0x01 || sibling || cur)`.
   - Otherwise reject.
9. Accept iff `cur == root`.

### 4.4 Size + index binding

Committing only the root (the Bitcoin Merkle convention) is insufficient
for VRT1's threat model: an adversary who finds two different leaf sets
that hash to the same root could falsely claim inclusion of leaves
never actually attested. To defend against this, VRT1:

- Commits `leaf_count` on-chain as part of the `OP_RETURN` payload
  (Section 5).
- Requires `size` and `index` to be part of the proof object so the
  verifier can validate proof depth and direction-bits independently
  of the proof bytes themselves.

See `test-vectors/merkle.json` for canonical trees of sizes 1–8 with
proofs for every leaf.

---

## 5. Bitcoin Anchor

### 5.1 Wire format

The Bitcoin commitment is a single `OP_RETURN` output in a Bitcoin
transaction. The exact payload (the bytes pushed after the
`OP_RETURN` opcode and length byte) is 49 octets:

```
| tag     | version | epoch       | leaf_count  | merkle_root |
| 4 bytes | 1 byte  | 8 bytes BE  | 4 bytes BE  | 32 bytes    |
```

| Field        | Bytes | Encoding                                       |
|--------------|-------|------------------------------------------------|
| `tag`        | 4     | ASCII `VRT1` (`0x56 0x52 0x54 0x31`).          |
| `version`    | 1     | Protocol version. MUST be `0x01` for VRT1.     |
| `epoch`      | 8     | Big-endian unsigned 64-bit integer.            |
| `leaf_count` | 4     | Big-endian unsigned 32-bit integer. Implementations MUST NOT produce epochs with more than 2^32 − 1 attestations. |
| `merkle_root`| 32    | Raw Merkle root bytes (NOT hex-encoded).       |

Total: **49 bytes**, which fits in a single direct push opcode
(values `0x01` through `0x4b`), keeping the `OP_RETURN` output
"standard" under Bitcoin Core relay policy.

### 5.2 Script

The full `OP_RETURN` output script is:

```
0x6a 0x31 <49 bytes of payload as above>
```

Where `0x6a` is `OP_RETURN` and `0x31` is the push-49-bytes opcode.

The `OP_RETURN` output MUST have a value of 0 satoshis.

### 5.3 Transaction structure

The anchor transaction:

- **MUST** be a valid Bitcoin transaction per [BIP-141] / [BIP-143].
- **SHOULD** be a P2WPKH (`OP_0 <20-byte hash160>`) input → P2WPKH
  change + `OP_RETURN` outputs. Other input/output types are not
  prohibited, but reference implementations use P2WPKH for
  simplicity and lowest fee.
- **MUST** be signed using the segwit BIP-143 sighash construction
  with `SIGHASH_ALL`.
- The `txid` displayed in block explorers is the
  reverse-byte-order hex of `d(non_witness_serialization)`.

### 5.4 Anchor key derivation

To avoid using the oracle's identity key for Bitcoin signing,
implementations SHOULD derive a separate 32-byte private scalar for
anchor signing via:

```
anchor_privkey := tagged_hash("VRT1/anchor-key", oracle_privkey)
```

The corresponding compressed pubkey is then used as the P2WPKH input
that funds the anchor. Operators who fund a different UTXO with a
different key MAY supply that key directly to the anchor builder;
implementations MUST validate that the supplied UTXO's pubkey hash
matches the signing key, since the resulting transaction would
otherwise be unspendable.

### 5.5 Broadcast

This specification does not mandate how the anchor transaction is
broadcast. Reference implementations support:

- HTTP POST to `mempool.space/{network}/api/tx` (no auth, public).
- JSON-RPC `sendrawtransaction` against a `bitcoind` node.

Implementations MAY support other paths (BlockCypher, Blockstream,
Esplora, etc.).

---

## 6. Checkpoint Event

### 6.1 Purpose

At epoch close, the oracle publishes a *checkpoint event* that:

- Names the Merkle root and leaf count committed on-chain.
- Identifies the anchor transaction (its txid).
- Provides a Nostr-side reference that consumers can subscribe to
  and verify offline.

### 6.2 Wire format

A checkpoint is a NIP-01 Nostr event with:

| Field         | Value                                                    |
|---------------|----------------------------------------------------------|
| `kind`        | `30079` (parameterized-replaceable per NIP-33).          |
| `pubkey`      | The oracle's x-only pubkey, hex.                         |
| `created_at`  | Unix seconds at epoch close.                             |
| `tags`        | At minimum `["d", "checkpoint:<epoch>"]` and `["v", "VRT1.1"]`. |
| `content`     | Canonical JSON object with the fields below.             |

The `content` JSON object:

```json
{
  "epoch":  <integer>,
  "root":   "<64-char lowercase hex>",
  "count":  <integer>,
  "anchor_txid": "<64-char lowercase hex or null>"
}
```

If `anchor_txid` is `null`, no Bitcoin anchor was produced for that
epoch. Implementations consuming the checkpoint MUST NOT treat such
checkpoints as Bitcoin-anchored.

**Note:** Unlike attestation events (Section 7), checkpoint content
is stored as raw JSON rather than base64 because checkpoint payloads
are small and useful for relay-side filtering on structured fields.

### 6.3 Recommended tags

Implementations SHOULD include the following additional tags for
relay-side filterability:

- `["root", "<hex>"]`
- `["anchor", "<txid hex>"]` (only when `anchor_txid` is non-null)

### 6.4 Signature

The event id and signature follow NIP-01 exactly. Specifically, the
event id is the lowercase hex of SHA-256 over the canonical JSON of:

```json
[0, pubkey, created_at, kind, tags, content]
```

with `separators=(",", ":")` per Section 1.4. The signature is the
BIP-340 Schnorr signature of the event id bytes under the oracle's
private key.

---

## 7. Attestation Event (Nostr Wrapper)

### 7.1 Purpose

Per-attestation events let consumers fetch a specific attestation
from any Nostr relay without trusting the oracle's HTTP infrastructure.

### 7.2 Wire format

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| `kind`       | `30078` (parameterized-replaceable per NIP-33).             |
| `pubkey`     | The oracle's x-only pubkey, hex.                            |
| `created_at` | Unix seconds — matches `attestation.ts`.                    |
| `tags`       | At minimum `["d", "<epoch>:<index_in_epoch>"]`, `["model", "<model_id>"]`, `["v", "VRT1.1"]`, `["epoch", "<epoch>"]`, `["input", "<input_hash>"]`. |
| `content`    | Base64 of the canonical JSON of `{"attestation": <payload>, "sig": <hex>}`. |

### 7.3 Verification

A consumer that fetches an attestation event MUST:

1. Verify the Nostr event id + Schnorr sig per NIP-01.
2. Base64-decode `content` and parse as JSON; extract `attestation`
   and `sig`.
3. Verify `event.pubkey == attestation.oracle`. (Round-2 finding:
   without this, a third party could re-wrap a valid SignedAttestation
   in a Nostr event signed by an unrelated key.)
4. Verify the inner attestation signature per Section 3.

---

## 8. Agent Actions (kind 1990)

VRT1 defines a parallel attestation type for autonomous agents to
sign records of what they did — reviews, vouches, disputes, trades,
or arbitrary semantic actions.

### 8.1 Schema

| Field            | Type    | Required | Description                              |
|------------------|---------|----------|------------------------------------------|
| `agent`          | string  | Yes      | 64-char hex of agent's x-only pubkey.    |
| `action_type`    | string  | Yes      | E.g. `"review"`, `"vouch"`, `"dispute"`. |
| `target`         | string  | Yes      | What the action is about (URL, agent pubkey, prior action_id, etc.). |
| `params`         | object  | Yes      | Action-specific parameters. MUST be a JSON object. |
| `outcome`        | object  | Yes      | Observable result. MUST be a JSON object. |
| `ts`             | integer | Yes      | Unix seconds.                            |
| `parent_action`  | string  | No       | Action id this action references (vouch/dispute target). |
| `v`              | integer | Yes      | Protocol version. MUST be `1`.           |

`null` `parent_action` MUST be omitted from the canonical payload.
Empty-string `parent_action` MUST be normalized to omitted (round-3
fix; otherwise two semantically-equivalent no-parent actions produce
different `action_id`s).

### 8.2 Digest and signature

```
action_id := hex(tagged_hash("VRT1/agent-action", canonical_json(payload)))
sig       := hex(schnorr_sign(bytes.fromhex(action_id), agent_privkey))
```

The `action_id` doubles as the unique identifier and the signing
digest. Two semantically-identical actions from the same agent
produce the same `action_id`.

### 8.3 Nostr wrapping

| Field        | Value                                              |
|--------------|----------------------------------------------------|
| `kind`       | `1990` (regular event — actions are non-repudiable). |
| `pubkey`     | Agent's x-only pubkey, hex.                        |
| `tags`       | At minimum `["d", "<action_id>"]`, `["t", "<action_type>"]`, and `["e", "<parent_action>"]` when `parent_action` is set. |
| `content`    | Base64 of `{"action": <payload>, "sig": <hex>}`.   |

Implementations consuming agent-action events MUST verify BOTH the
outer Nostr event signature AND the inner action signature, AND that
`event.pubkey == action.agent`. (Round-3 finding: failing to verify
the inner sig lets an attacker re-wrap a valid action under an
unrelated outer Nostr signature.)

### 8.4 Reserved action types

| Type        | Meaning                                                 |
|-------------|---------------------------------------------------------|
| `review`    | The agent examined `target` and produced a verdict.     |
| `vouch`     | The agent endorses the action referenced by `parent_action`. |
| `dispute`   | The agent rejects the action referenced by `parent_action`. |
| `trade`     | The agent executed a transfer / trade.                  |
| `consume`   | The agent consumed a resource (paid call, energy).      |
| `message`   | The agent sent a message to another agent.              |
| `infer`     | The agent ran a model on `params.input` producing `outcome.output` (bridge to Section 3). |

Implementations MAY define additional action types. The reserved
types above are those the reference reputation aggregator
([vrt1-agents]) understands semantically; other types are stored and
queryable but do not contribute to vouch/dispute graph metrics.

`key_registry_snapshot` (Section 8.5) is reserved separately, as spec
infrastructure rather than as a reputation signal: it is stored,
verifiable and anchorable, but it makes no claim about any agent's
conduct and contributes nothing to the vouch/dispute graph.

### 8.5 Key registry snapshots

An attester that publishes a signing-key registry has a circularity
problem: the registry lives on the attester's own server, and its
`valid_from` / `valid_until` windows are self-asserted with no external
timestamp. A consumer asking "was this key inside its published window
when it signed?" is trusting the same party whose signature is in
question.

A `key_registry_snapshot` is an agent action whose payload is the
registry itself. Anchored under Section 5, it moves the registry's
trust from the operator's web server to Bitcoin. Chained through
`parent_action`, it additionally proves **completeness**: without a
chain, publishing snapshot A and snapshot C while silently omitting B
is undetectable, and that omission is exactly how a briefly-active key
would be hidden. Existence and completeness are different claims, and
key lifecycle rests on the second.

| Field                            | Type    | Required | Description                          |
|----------------------------------|---------|----------|--------------------------------------|
| `action_type`                    | string  | Yes      | MUST be `"key_registry_snapshot"`.   |
| `target`                         | string  | Yes      | Operator-chosen registry identifier. MUST be stable across the chain. |
| `params.snapshot.keys`           | array   | Yes      | Key entries. Order is significant.   |
| `params.snapshot.schema_version` | integer | Yes      | Snapshot schema version.             |
| `params.snapshot.ts`             | integer | Yes      | Unix seconds at snapshot construction. |
| `outcome.active_count`           | integer | Yes      | Entries with `revoked == false`.     |
| `outcome.revoked_count`          | integer | Yes      | Entries with `revoked == true`.      |
| `parent_action`                  | string  | No       | Previous snapshot's `action_id`. Omitted for the genesis snapshot. |

Each entry of `params.snapshot.keys`:

| Field         | Type            | Required | Description                                    |
|---------------|-----------------|----------|------------------------------------------------|
| `key_id`      | string          | Yes      | Operator-scoped stable identifier.              |
| `key_type`    | string          | Yes      | What `public_key` holds: `eth_address`, `secp256k1_xonly`, `secp256k1_compressed`, `ed25519`. Extensible. |
| `public_key`  | string          | Yes      | Hex, `0x` stripped and lowercased per Section 1.5. |
| `custody`     | string          | Yes      | Declared custody of the private key.            |
| `revoked`     | boolean         | Yes      | Whether the key is revoked.                     |
| `valid_from`  | integer         | Yes      | Unix seconds.                                   |
| `valid_until` | integer or null | Yes      | Unix seconds, or `null` for open-ended.         |

Rules:

- `keys` order **MUST** be preserved. Canonical JSON (Section 1.4)
  sorts object keys; it does not sort arrays. An implementation that
  sorts `keys` "for determinism" produces a different `action_id`.
- A `null` `valid_until` **MUST** be serialized as `null`, **not**
  omitted. This is the opposite of the `parent_action` rule in Section
  8.1, and deliberately so: an omitted `parent_action` and a `null` one
  mean the same thing, whereas an omitted `valid_until` and a `null`
  one do not. Two spellings of "no expiry" would otherwise produce two
  `action_id`s for one registry.
- `valid_from`, `valid_until` and `ts` **MUST** be integer Unix
  seconds. Date-time strings are rejected because one instant has many
  legal RFC 3339 spellings (`2026-08-05`, `2026-08-05T00:00:00Z`,
  `2026-08-05T00:00:00.000+00:00`), and a canonical record cannot
  admit more than one spelling of the same value.
- `key_type` is required so that "did a registered key sign this
  receipt?" is mechanizable. An Ethereum address is a hash of a public
  key, not a public key; a verifier cannot check membership without
  knowing which it holds.
- `active_count` and `revoked_count` **MUST** equal the partition of
  `keys` on `revoked`. A verifier **MUST** reject a snapshot whose
  counts disagree with its own `keys` array. "Active" here means "not
  revoked" — not "currently inside its window," since window
  membership is evaluated against a signing time, not summarized in
  the record.

The key that signs a snapshot (`agent`) **SHOULD** itself appear in
`params.snapshot.keys` with `key_type: "secp256k1_xonly"`. Without it
the registry authenticates every key except the one that authenticated
the registry, and the circularity the type exists to remove simply
moves up one level.

Given that, a chain of snapshots is also a **key rotation
authorization** chain, and not merely a history:

- A non-genesis snapshot **MUST** be signed by a key that its
  `parent_action` snapshot lists with `revoked: false` and whose
  validity window contains the successor's `ts`. An outgoing signing
  key authorizes its replacement; a key that no ancestor vouches for
  cannot introduce itself.
- A successor that fails this check **MUST** be rejected even though
  its own signature verifies. This is the one failure mode in this
  specification that is invisible in isolation: the record is
  internally valid and is refused by its context.
- `params.snapshot.ts` **MUST NOT** be later than the action's `ts`. A
  registry may be read at one moment and published at a later one; it
  cannot be read from the future.

The genesis snapshot has no parent and therefore cannot be authorized
by one. Its trust root is explicitly **not** cryptographic and
implementations **MUST NOT** present it as though it were. It rests on
two things: the Bitcoin anchor, which fixes the genesis in time so that
a later-manufactured "original" is detectable, and an out-of-band
binding of the agent pubkey to the operator, published on a channel the
operator controls. Every rotation after genesis is chained and checkable;
that first hop is a human trust decision, and saying so is the honest
description of what the anchor does and does not buy.

`custody` values: `hot_process`, `kms`, `hsm`, `offline`,
`air_gapped`, `unknown`. **The enumeration is unordered.** VRT1 supplies
the vocabulary so that custody is comparable across attesters; it does
not rank the values, does not endorse any of them, and does not treat
`unknown` as a failure. Consistent with Section 12.2: VRT1 attests that
a record is authentic and unaltered, never that the arrangements it
describes are adequate.

Validity is evaluated **at signing time**. A receipt signed while its
key was inside its published window remains verifiable after that
window closes; revocation stops forward trust and does not reach
backward into an anchored set.

*Type contributed by Insight (`oracleinsight.xyz`), who built the first
implementation as a vendor-namespaced record. It is registered
un-namespaced because every attester that publishes a key registry has
the same problem, and two records that mean the same thing should not
fail to interoperate over a prefix.*
### 8.6 Vendor action type directory

Section 8.4 permits an implementation to define its own action type,
and most will. That leaves a gap at the other end: a consumer holding
one of those records has an `action_type` string and nothing else, and
no way to find out what its fields mean without being told where to
look. Fixing the meaning of a type is not the same as making it
findable.

`registry/vendor-action-types.json` lists vendor-defined types with a
pointer to each one's declaration.

**Entries are pointers. This specification does not copy
declarations.** A declaration lives in exactly one place, the
operator's own repository, because two copies of a truth is none: if
the same document lived here as well, the two would eventually diverge
and a reader would have to decide which to trust. One file, one hash,
one place to check.

Each entry **MUST** carry:

- the `action_type` string exactly as it appears in records,
- the operator and the domain it publishes under,
- a declaration URL naming an **immutable revision**, so the bytes
  cannot change under a reader,
- the `sha256` and byte count of the bytes served at that revision,
- the date VRT1 fetched and verified them.

A verifier **MUST** hash the bytes exactly as served, and **MUST NOT**
parse the declaration and re-serialize it before hashing. A
re-serialization is a different byte string whose digest matches
nothing anyone has published: the first entry in the directory is 7006
bytes as served and 7386 bytes re-emitted with two-space indentation,
identical in content and neither digest equal to the other.

An operator revising a declaration produces a new revision and a new
entry. The directory records what was checked and when; it does not
track what is current somewhere else.

**Listing is not endorsement.** It records that a type exists, where
its declaration is, and what those bytes hashed to on a date. It says
nothing about whether the operator's verdicts are correct, whether the
service is available, or whether the declaration describes what that
service does by default. That is the same boundary Section 12.2 draws
around anchoring, applied one level up.
---

## 9. kWh Measurements (kind 1991)

A parallel attestation type for devices to sign records of their own
energy consumption.

### 9.1 Schema

| Field          | Type    | Required | Description                              |
|----------------|---------|----------|------------------------------------------|
| `device`       | string  | Yes      | 64-char hex of device's x-only pubkey.   |
| `window_start` | integer | Yes      | Unix seconds, start of measurement window. |
| `window_end`   | integer | Yes      | Unix seconds, end of measurement window. MUST be >= `window_start`. |
| `kwh`          | number  | Yes      | Kilowatt-hours consumed during the window. MUST be >= 0. |
| `source`       | string  | Yes      | Short identifier of the measurer (`"rapl"`, `"shelly-v3"`, etc.). |
| `model_id`     | string  | Yes      | Versioned tag of the measurement model.  |
| `v`            | integer | Yes      | Protocol version. MUST be `1`.           |
| `nonce`        | string  | No       | Optional random hex for unlinkability.   |

`kwh` MUST be rounded to 9 decimal places (nanowatt-hour resolution)
before serialization — this is well below any real-world measurement
noise and ensures bit-identical digests across IEEE-754 implementations.

### 9.2 Digest and signature

```
measurement_id := hex(tagged_hash("VRT1/kwh", canonical_json(payload)))
sig            := hex(schnorr_sign(bytes.fromhex(measurement_id), device_privkey))
```

### 9.3 Nostr wrapping

| Field        | Value                                                  |
|--------------|--------------------------------------------------------|
| `kind`       | `1991` (regular event).                                |
| `pubkey`     | Device's x-only pubkey, hex.                           |
| `tags`       | At minimum `["d", "<measurement_id>"]`, `["source", "<source>"]`, `["window", "<start>", "<end>"]`. |
| `content`    | Base64 of `{"measurement": <payload>, "sig": <hex>}`.  |

VRT1 implementations MUST NOT emit a self-pointing `["p", "<device_pubkey>"]`
tag. Per NIP-01, "p" tags reference OTHER pubkeys (mentions/replies);
self-references break consumer filters and confuse standard Nostr
clients. The device pubkey is already queryable via the standard
`authors` REQ filter on the event's `pubkey` field.

### 9.4 Fraud-resistance scope

The cryptographic layer (this section) proves that a signature is
valid under a specific device key. It does NOT prove the measurement
is physically true; a rogue device can sign arbitrary `kwh` values.
Fraud resistance is the consumer's responsibility and SHOULD include:

- Aggregator-level detection of same-device overlapping windows
  (impossible physically; evidence of clock-skew bug or
  double-counting).
- Economic rate-limits (rejecting `kwh > plausible_max_for_device`).
- TEE-based attestation of the measurement code (out of scope for VRT1.1).
- Utility-meter integration where the meter is the trusted measurement
  endpoint.

---

## 10. L402 Lightning Paywall

VRT1 implementations that expose paid endpoints (premium attestations,
bulk fetches, write operations) SHOULD use L402 ([formerly LSAT])
for per-call monetization, per [L402 spec].

### 10.1 Server behavior

On an unauthenticated request to a protected endpoint, the server
MUST respond with HTTP 402 Payment Required and a `WWW-Authenticate`
header of the form:

```
WWW-Authenticate: L402 macaroon="<token>", invoice="<bolt11>"
```

The `<token>` is a URL-safe base64 of a JSON object as per
[Macaroon-format below]; `<bolt11>` is a real BOLT-11 Lightning invoice.

### 10.2 Macaroon format

A VRT1 L402 macaroon is a JSON object:

```json
{
  "id": "<resource_id>",
  "ph": "<payment_hash_hex>",
  "c":  ["<caveat1>", "<caveat2>", ...],
  "t":  "<base64(hmac_sha256(secret, canonical_json({id,ph,c})))>"
}
```

The macaroon is URL-safe base64-encoded for transport.

**Note:** This is a simplified JSON structure, not the chained-HMAC
binary format used by libmacaroons / pymacaroons. Third parties
cannot add caveats without the server secret (no additive
attenuation). Implementations that require caveat delegation SHOULD
use standard macaroons and adapt the authorize algorithm accordingly.

Implementations:

- **MUST** include at least one `exp=<unix_ts>` caveat. The
  reference implementation rejects macaroons without an `exp=`
  caveat at `authorize` time (round-2 hardening). Caveats are
  UTF-8 strings of the form `key=value` where `key` is a
  non-empty ASCII identifier and `value` is the remainder after
  the first `=`. Keys are case-sensitive. This specification
  defines only `exp`; additional caveat keys (e.g., `scope`,
  `rate`) are reserved for VRT1.2.
- **MUST** use HMAC-SHA-256 with a server-only secret of at least
  16 octets.
- **MUST** use `hmac.compare_digest` (or equivalent constant-time
  comparison) when verifying the tag.

### 10.3 Client behavior

After paying the Lightning invoice, the client obtains the preimage
and retries the request with:

```
Authorization: L402 <macaroon_token>:<preimage_hex>
```

The scheme `L402` is case-insensitive per [RFC 7235] (round-3 fix).

### 10.4 Server `authorize` algorithm

The server MUST validate, in order:

1. The header begins with `L402 ` (case-insensitive on the scheme).
2. The credentials contain exactly one `:` separator.
3. The macaroon decodes and its tag verifies under the server secret.
4. `macaroon.id == resource_id` (the resource the client is requesting).
5. `bytes.fromhex(preimage)` is well-formed.
6. `hmac.compare_digest(hex(sha256(preimage)), macaroon.ph) == True`.
7. **At least one** `exp=<ts>` caveat is present, and **every** such
   caveat satisfies `int(ts) >= now`.
8. (OPTIONAL) The Lightning backend reports the invoice as settled.
   This MUST NOT grant access on its own — it is an additional
   revocation signal only.

The order of checks 6 and 7 matters: expiry MUST be checked before
any backend RPC, otherwise replayed expired tokens become an
amplification vector against the LN node (round-2 finding).

---

## 11. Verification Algorithm

This section specifies the FULL binding chain a third-party verifier
runs to validate that a specific VRT1 attestation is anchored to
Bitcoin. Each layer below is independently checkable; the algorithm
fails closed if any layer fails or if a layer is supplied but cannot
be bound to the rest of the chain.

### 11.1 Inputs

| Input                  | Required? | Source                          |
|------------------------|-----------|---------------------------------|
| `signed_attestation`   | Yes       | Section 3 wire format.          |
| `nostr_event`          | No        | Section 7 wrapper.              |
| `merkle_proof`         | No        | Section 4 inclusion proof.      |
| `checkpoint_event`    | No        | Section 6 wire format.          |
| `anchor_raw_tx_hex`    | No        | Raw Bitcoin tx hex from a block explorer or node. |

### 11.2 Output

A `VerificationResult` with one of `True | False | None` per layer
and an overall `ok` boolean. `None` MUST be used for any layer whose
input was not supplied; `False` means the input was supplied but
failed verification.

### 11.3 Algorithm

In order:

1. **Schnorr (Section 3).** Compute `attestation_digest` and verify
   the Schnorr signature against `attestation.oracle`. If invalid:
   `schnorr_ok := False; ok := False`.

2. **Nostr event (Section 7), if supplied.** Verify the event id +
   Schnorr sig per NIP-01. Verify `event.pubkey == attestation.oracle`.
   If invalid: `nostr_event_ok := False`.

3. **Merkle proof (Section 4), if supplied.** Verify
   `proof.leaf == attestation_digest`. If valid, run the proof
   verification (Section 4.3). Otherwise: `merkle_ok := False`.

4. **Checkpoint event (Section 6), if supplied.**
   - **REQUIRE** that `merkle_proof` is also supplied AND that
     the Merkle proof verified successfully (step 3 passed).
     Without a valid proof, the digest cannot be bound to the
     checkpoint's root. If not supplied or failed:
     `checkpoint_ok := False`.
   - Verify the Nostr event signature.
   - Verify `event.pubkey == attestation.oracle`.
   - Parse the signed content as canonical JSON; extract `epoch`,
     `root`, `count`, `anchor_txid`.
   - Verify `signed_attestation.attestation.epoch == content.epoch`
     (integer comparison; reject on TypeError from null/list/dict).
   - Verify `merkle_proof.root.hex() == content.root`.
   - Verify `merkle_proof.size == content.count`.

5. **Anchor tx (Section 5), if supplied.**
   - **REQUIRE** that `merkle_proof` is also supplied (same reason
     as checkpoint). If not supplied: `anchor_ok := False`.
   - Parse the raw tx hex; extract the OP_RETURN output's pushed
     payload. Reject if there is no `OP_RETURN` output, the
     payload is not exactly 49 bytes, the tag is not `VRT1`, or
     the version byte is not the supported value.
   - Verify `parsed.epoch == signed_attestation.attestation.epoch`.
   - Verify `parsed.merkle_root == merkle_proof.root`.
   - Verify `parsed.leaf_count == merkle_proof.size`.
   - If `checkpoint_event` was also supplied, verify
     `parsed.merkle_root.hex() == content.root` AND
     `parsed.leaf_count == content.count`.

6. **Final `ok`.** Defined as:
   ```
   ok := schnorr_ok
         AND (nostr_event_ok is not False)
         AND (merkle_ok is not False)
         AND (checkpoint_ok is not False)
         AND (anchor_ok is not False)
   ```
   That is: the attestation MUST verify, and every layer that was
   supplied AND failed brings `ok` to False. Layers not supplied
   (`None`) do not influence `ok`.

---

## 12. Security Considerations

### 12.1 Threat model summary

| Adversary capability                  | Defended against by                             |
|----------------------------------------|-------------------------------------------------|
| Forge attestation                      | BIP-340 Schnorr (Section 3.3)                   |
| Tamper attestation post-sign           | Schnorr verification (Section 11.3 step 1)      |
| Forge Nostr event under another key    | Section 11.3 step 2 (event.pubkey ↔ oracle)     |
| Re-wrap signed attestation in forged Nostr | Section 7.3 (inner+outer sig + pubkey checks) |
| Claim inclusion of non-leaf            | Merkle proof + leaf-vs-internal prefixes (4.1)  |
| Two leaf sets, same root (CVE-2012-2459) | RFC-6962 prefixes + on-chain leaf_count (4.4) |
| Publish checkpoint with different root than anchored | Section 11.3 step 5 (anchor↔checkpoint cross-check) |
| Replay expired L402 token              | Mandatory exp= caveat (Section 10.2)            |
| Replay flood expired tokens for DoS    | Expiry check before backend RPC (Section 10.4)  |
| L402 macaroon HMAC forgery             | Secret ≥16 bytes, constant-time compare (10.2)  |
| L402 header injection via pay_callback | 64-hex preimage regex (reference impl)          |

### 12.2 What VRT1 does NOT defend against

- **Truth of the attested output.** VRT1 proves an oracle signed a
  specific claim; it does not prove the claim is correct. (For AI
  inference, this is the well-known "garbage in, garbage out
  verifiably" gap. TEE-based attestation could close it; out of
  scope for VRT1.1.)
- **Sybil resistance on agent reputation.** An operator with N
  fresh BIP-340 keys can mint N vouches for one target. Section 8.4
  is explicit about this. Reputation consumers MUST layer external
  trust signals on top.
- **Physical truth of kWh measurements.** A rogue device can sign
  arbitrary `kwh` values. Section 9.4 enumerates higher-layer
  mitigations.

### 12.3 Key management

VRT1 oracles and agents:

- MUST generate private keys with a cryptographically secure RNG
  capable of producing scalars in `[1, n-1]` for the secp256k1 group
  order `n` (rejection-sample if the underlying RNG can produce
  values outside the range).
- SHOULD store keys with restrictive file permissions (mode `0600`
  on POSIX). The reference implementation uses
  `os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)` to eliminate the
  TOCTOU window between file creation and `chmod`.
- SHOULD use different keys for different roles (oracle identity vs
  anchor signing — Section 5.4).

### 12.4 Replay considerations

- VRT1 attestations include `ts` and `epoch` in the digest, so an
  attestation cannot be replayed for a different epoch.
- L402 macaroons include `payment_hash` in the HMAC tag, so a
  macaroon issued for one invoice cannot be paired with a different
  invoice's preimage.
- L402 macaroons do NOT include a per-request nonce, so a valid
  `(macaroon, preimage)` pair authorizes UNLIMITED calls within the
  `exp=` window. Implementations that require single-use semantics
  MUST track redemptions out-of-band (e.g., spent-preimage set).

---

## 13. Test Vectors

This specification ships with the following test vectors under
`test-vectors/`:

| File                              | Covers                       |
|-----------------------------------|------------------------------|
| `attestation.json`                | Section 3 (sign, digest, roundtrip) |
| `merkle.json`                     | Section 4 (trees of size 1, 2, 3, 4, 5, 7, 8 with proofs) |
| `op_return.json`                  | Section 5 (49-byte payload roundtrip) |
| `nostr_attestation_event.json`    | Section 7 (kind 30078 roundtrip) |
| `nostr_checkpoint_event.json`     | Section 6 (kind 30079 roundtrip) |
| `agent_action.json`               | Section 8 (kind 1990 sign+verify) |
| `kwh_measurement.json`            | Section 9 (kind 1991 sign+verify) |
| `key_registry_snapshot.json`      | Section 8.5 (chained snapshots + 5 negatives) |

The vendor action type directory (Section 8.6) lives at
`registry/vendor-action-types.json`, outside `test-vectors/`, because it
records external pointers rather than reproducible vectors.

Implementations of VRT1 SHOULD reproduce these vectors byte-for-byte
from the included payloads, and SHOULD ship a test that asserts
their implementation can verify each.

These vectors cover positive-path round-trips, except
`key_registry_snapshot.json`, which also ships negatives. A negative
vector MUST be published as literal canonical bytes plus its expected
`action_id`, and MUST violate exactly one rule. A negative described as
a mutation procedure tests the reader's reconstruction rather than the
rule, and two implementations can both report green while checking
different things. Remaining negatives (null output, oversized epoch,
malformed hex, invalid signatures) are reserved for a future
conformance test suite.

---

## 14. References

- **[RFC 2119]:** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC 2104]:** Krawczyk, H., Bellare, M., Canetti, R., "HMAC:
  Keyed-Hashing for Message Authentication", RFC 2104, February 1997.
- **[RFC 7235]:** Fielding, R., Reschke, J., "Hypertext Transfer
  Protocol (HTTP/1.1): Authentication", RFC 7235, June 2014.
- **[RFC 6962]:** Laurie, B., Langley, A., Kasper, E., "Certificate
  Transparency", RFC 6962, June 2013. (Inspiration for the
  leaf/internal-prefix domain separation in Section 4.1.)
- **[FIPS-180-4]:** NIST, "Secure Hash Standard", FIPS PUB 180-4,
  August 2015.
- **[BIP-340]:** Wuille, P., Nick, J., Towns, T., "Schnorr Signatures
  for secp256k1", BIP-340, January 2020.
- **[BIP-141]:** Lombrozo, E., Lau, J., Wuille, P., "Segregated
  Witness (Consensus layer)", BIP-141, December 2015.
- **[BIP-143]:** Lau, J., Wuille, P., "Transaction Signature
  Verification for Version 0 Witness Program", BIP-143, January 2016.
- **NIP-01:** "Basic protocol flow description", Nostr Implementation
  Possibilities, https://github.com/nostr-protocol/nips/blob/master/01.md
- **NIP-33:** "Parameterized Replaceable Events", https://github.com/nostr-protocol/nips/blob/master/33.md
- **L402 spec:** "Lightning HTTP 402 (L402) Protocol",
  https://docs.lightning.engineering/the-lightning-network/l402
- **CVE-2012-2459:** Bitcoin Merkle tree second-preimage attack via
  duplicated tail. https://nvd.nist.gov/vuln/detail/CVE-2012-2459

---

## Appendix A — Reference Implementation

The canonical implementation of VRT1 is:

- **Oracle + protocol core:** https://github.com/Ifasola34/veritas
- **Third-party verifier:** https://github.com/Ifasola34/vrt1-verifier
- **Agent actions library:** https://github.com/Ifasola34/vrt1-agents
- **kWh attestation library:** https://github.com/Ifasola34/vrt1-kwh
- **L402 paywall library:** https://github.com/Ifasola34/l402-py
- **End-to-end demo:** https://github.com/Ifasola34/vrt1-demo
- **Protocol specification:** https://github.com/Ifasola34/vrt1-spec

Total LOC across all 7 repos: ~8,000 lines of library code + ~8,600
lines of tests. All MIT-licensed.

## Appendix B — Open Questions / Future Work

The following are NOT specified in VRT1.1 but are flagged for
potential inclusion in VRT1.2:

- **TEE attestation** for the model code (closes the "did the
  claimed model actually run" gap).
- **FROST threshold signing** for the oracle key (eliminates the
  single-key-leak failure mode).
- **Multi-relay Nostr publication strategy** (current spec is
  single-relay agnostic).
- **kWh-to-mainnet-token bridge semantics** (current spec stops at
  signed measurements; consumers define mint policy).
- **Aggregator-level Sybil-resistance heuristics** for agent
  reputation (current spec is explicit that this is out of scope).

Contributions to either this spec or the reference implementations
are welcome via GitHub pull request.
