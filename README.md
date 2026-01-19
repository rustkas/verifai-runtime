# VerifAI Runtime

Deterministic inference runtime that produces a signed Proof Artifact binding:
- model hash
- input hash
- output hash
- execution trace Merkle root
- runtime id

## MVP
- Logistic regression + 2-layer MLP inference
- Canonical binary encoding for inputs, models, outputs, events
- Merkle trace root + Ed25519-signed `ProofArtifactV0/V1`
- CLI: `hash-model`, `prove`, `verify` with JSON/quiet modes
- Per-vector determinism gate + test fixtures

## CLI highlights
- `verifai hash-model --model model.json --out model.bin`
- `verifai prove …` accepts `--out-output`, `--out-artifact`, optional `--out-model-bin`, `--out-input-bin`, `--print-json`, `--json-file`, `--quiet`, `--attest`
- `verifai verify …` replays inference, checks hashes/trace/root/signature and, when requested, emits the same metadata JSON

## Test vectors
- Logistic cases: `test-vectors/case-1`, `case-2`, `case-3` (each has `model.json`, `input.json`, canonical `.bin`, expected output/artifact)
- MLP case: `test-vectors/mlp-case-1` covering the 2-layer network with canonical `.bin` bundles

## Regenerating vectors
Run the helper example to canonicalize JSON inputs/models and refresh the expected `.bin` outputs:

```
cargo run -p verifai-runtime --example update_test_vectors
```
