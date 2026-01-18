use verifai_core::artifact_bin::{ProofArtifactV0, PROOF_ARTIFACT_V0_LEN};
use verifai_core::hash::sha256;
use verifai_core::merkle::trace_root_from_event_bytes;

use crate::{VerifaiError};
use crate::lr::run_lr_v0;

pub fn prove_lr_v0(
    runtime_id: [u8; 32],
    signing_key_bytes: [u8; 32],
    model_bin: &[u8],
    input_bin: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VerifaiError> {
    let run = run_lr_v0(model_bin, input_bin)?;

    let output_bin = run.output.encode_bin();

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(&output_bin);

    let event_bytes: Vec<Vec<u8>> = run.events.iter().map(|e| e.encode_bin()).collect();
    let trace_root = trace_root_from_event_bytes(&event_bytes);

    let mut artifact = ProofArtifactV0 {
        version: 0,
        runtime_id,
        model_hash,
        input_hash,
        output_hash,
        trace_root,
        sig_pubkey: [0u8; 32],
        signature: [0u8; 64],
    };

    artifact.sign_detached(signing_key_bytes).map_err(|_| VerifaiError::CoreDecode)?;

    let artifact_bin = artifact.encode_bin();
    if artifact_bin.len() != PROOF_ARTIFACT_V0_LEN {
        return Err(VerifaiError::CoreDecode);
    }

    Ok((output_bin, artifact_bin))
}

pub fn verify_lr_v0(
    artifact_bin: &[u8],
    model_bin: &[u8],
    input_bin: &[u8],
    output_bin: &[u8],
) -> Result<(), VerifaiError> {
    let artifact = ProofArtifactV0::decode_bin(artifact_bin).map_err(|_| VerifaiError::CoreDecode)?;
    if artifact.version != 0 {
        return Err(VerifaiError::CoreDecode);
    }

    artifact.verify_signature().map_err(|_| VerifaiError::SignatureInvalid)?;

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(output_bin);

    if artifact.model_hash != model_hash || artifact.input_hash != input_hash || artifact.output_hash != output_hash {
        return Err(VerifaiError::HashMismatch);
    }

    let run = run_lr_v0(model_bin, input_bin)?;
    let recomputed_output_bin = run.output.encode_bin();
    if sha256(&recomputed_output_bin) != output_hash {
        return Err(VerifaiError::HashMismatch);
    }

    let event_bytes: Vec<Vec<u8>> = run.events.iter().map(|e| e.encode_bin()).collect();
    let trace_root = trace_root_from_event_bytes(&event_bytes);

    if artifact.trace_root != trace_root {
        return Err(VerifaiError::TraceMismatch);
    }

    Ok(())
}
