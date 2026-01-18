mod lr;
mod prove;

pub use prove::{prove_lr_v0, verify_lr_v0};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifaiError {
    CoreDecode,
    DimensionMismatch,
    SignatureInvalid,
    HashMismatch,
    TraceMismatch,
}
