mod lr;
mod mlp;
mod prove;

pub use prove::{prove_lr_v0, prove_mlp_v1, verify_lr_v0, verify_mlp_v1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifaiError {
    CoreDecode,
    DimensionMismatch,
    SignatureInvalid,
    HashMismatch,
    TraceMismatch,
}
