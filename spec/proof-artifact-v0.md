# Proof Artifact v0

Provides deterministic cryptographic proof for inference runs.

## Binary Layout
All fields little-endian, no padding.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | `version` (u16 = 0) |
| 2 | 32 | `runtime_id` (SHA-256 of runtime metadata) |
| 34 | 32 | `model_hash` (SHA-256 of canonical model) |
| 66 | 32 | `input_hash` (SHA-256 of canonical input) |
| 98 | 32 | `output_hash` (SHA-256 of canonical output) |
| 130 | 32 | `trace_root` (Merkle root over event leaves) |
| 162 | 32 | `sig_pubkey` (Ed25519 public key) |
| 194 | 64 | `signature` (Ed25519 over prefix + fields 0..5 + pubkey) |

Signature message uses prefix `b"VERIFAI\0ARTIFACT\0V0"` followed by version, runtime_id, model hash, input hash, output hash, trace root, and signing public key.

## Trace
Events encoded without maps, with tags 0x01 (OpLinear), 0x02 (OpActivation), 0x03 (OpOutput). Each leaf hash is `SHA256(0x00 || event_bytes)`; nodes are `SHA256(0x01 || left || right)` and odd levels duplicate the last node. Empty traces yield `SHA256(0x02)`.

## Encoding Helpers
Model, input, and output use fixed magics (`VFAIMDL0`, `VFAIINP0`, `VFAIOUT0`) followed by lengths and little-endian numeric values. Activation kinds: `1` for sigmoid, `2` for ReLU.
