# VerifAI Runtime

Deterministic inference runtime that produces a signed Proof Artifact binding:
- model hash
- input hash
- output hash
- execution trace Merkle root
- runtime id

## MVP
- Logistic regression inference
- Canonical binary encoding for hashing
- Merkle trace root
- Ed25519 signature
- CLI: prove / verify
