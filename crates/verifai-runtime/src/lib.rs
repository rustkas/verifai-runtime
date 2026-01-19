mod attester;
mod lr;
mod mlp;
mod prove;

pub use attester::{Attester, NoopAttester};
pub use prove::{
    artifact_version, prove_lr_v0, prove_lr_v1_with_attester, prove_mlp_v1, verify_lr_v0,
    verify_lr_v1, verify_mlp_v1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifaiError {
    CoreDecode,
    DimensionMismatch,
    SignatureInvalid,
    HashMismatch,
    TraceMismatch,
}
