use verifai_core::artifact_bin::{ProofArtifactV0, ProofArtifactV1, PROOF_ARTIFACT_V0_LEN};
use verifai_core::hash::sha256;
use verifai_core::merkle::trace_root_from_event_bytes;

use crate::attester::{Attester, NoopAttester};
use crate::lr::run_lr_v0;
use crate::mlp::run_mlp_v1;
use crate::VerifaiError;

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

    artifact
        .sign_detached(signing_key_bytes)
        .map_err(|_| VerifaiError::CoreDecode)?;

    let artifact_bin = artifact.encode_bin();
    if artifact_bin.len() != PROOF_ARTIFACT_V0_LEN {
        return Err(VerifaiError::CoreDecode);
    }

    Ok((output_bin, artifact_bin))
}

fn build_artifact_v1(
    runtime_id: [u8; 32],
    signing_key_bytes: [u8; 32],
    model_hash: [u8; 32],
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    trace_root: [u8; 32],
    attestation: verifai_core::attestation::AttestationBundle,
) -> Result<Vec<u8>, VerifaiError> {
    let mut artifact = ProofArtifactV1 {
        version: 1,
        runtime_id,
        model_hash,
        input_hash,
        output_hash,
        trace_root,
        sig_pubkey: [0u8; 32],
        signature: [0u8; 64],
        attestation,
    };
    artifact
        .sign_detached(signing_key_bytes)
        .map_err(|_| VerifaiError::CoreDecode)?;

    Ok(artifact.encode_bin())
}

pub fn prove_lr_v1_with_attester<A: Attester>(
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

    let attestation = A::attest(trace_root);
    let artifact_bin = build_artifact_v1(
        runtime_id,
        signing_key_bytes,
        model_hash,
        input_hash,
        output_hash,
        trace_root,
        attestation,
    )?;
    Ok((output_bin, artifact_bin))
}

pub fn verify_lr_v0(
    artifact_bin: &[u8],
    model_bin: &[u8],
    input_bin: &[u8],
    output_bin: &[u8],
) -> Result<(), VerifaiError> {
    let artifact =
        ProofArtifactV0::decode_bin(artifact_bin).map_err(|_| VerifaiError::CoreDecode)?;
    if artifact.version != 0 {
        return Err(VerifaiError::CoreDecode);
    }

    artifact
        .verify_signature()
        .map_err(|_| VerifaiError::SignatureInvalid)?;

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(output_bin);

    if artifact.model_hash != model_hash
        || artifact.input_hash != input_hash
        || artifact.output_hash != output_hash
    {
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

pub fn verify_lr_v1(
    artifact_bin: &[u8],
    model_bin: &[u8],
    input_bin: &[u8],
    output_bin: &[u8],
) -> Result<(), VerifaiError> {
    let artifact =
        ProofArtifactV1::decode_bin(artifact_bin).map_err(|_| VerifaiError::CoreDecode)?;
    if artifact.version != 1 {
        return Err(VerifaiError::CoreDecode);
    }

    artifact
        .verify_signature()
        .map_err(|_| VerifaiError::SignatureInvalid)?;

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(output_bin);

    if artifact.model_hash != model_hash
        || artifact.input_hash != input_hash
        || artifact.output_hash != output_hash
    {
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

    if artifact.attestation.measurement != trace_root {
        return Err(VerifaiError::TraceMismatch);
    }

    Ok(())
}

pub fn prove_mlp_v1(
    runtime_id: [u8; 32],
    signing_key_bytes: [u8; 32],
    model_bin: &[u8],
    input_bin: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VerifaiError> {
    let run = run_mlp_v1(model_bin, input_bin)?;

    let output_bin = run.output.encode_bin();

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(&output_bin);

    let event_bytes: Vec<Vec<u8>> = run.events.iter().map(|e| e.encode_bin()).collect();
    let trace_root = trace_root_from_event_bytes(&event_bytes);

    let attestation = NoopAttester::attest(trace_root);
    let artifact_bin = build_artifact_v1(
        runtime_id,
        signing_key_bytes,
        model_hash,
        input_hash,
        output_hash,
        trace_root,
        attestation,
    )?;

    Ok((output_bin, artifact_bin))
}

pub fn verify_mlp_v1(
    artifact_bin: &[u8],
    model_bin: &[u8],
    input_bin: &[u8],
    output_bin: &[u8],
) -> Result<(), VerifaiError> {
    let artifact =
        ProofArtifactV1::decode_bin(artifact_bin).map_err(|_| VerifaiError::CoreDecode)?;
    if artifact.version != 1 {
        return Err(VerifaiError::CoreDecode);
    }

    artifact
        .verify_signature()
        .map_err(|_| VerifaiError::SignatureInvalid)?;

    let model_hash = sha256(model_bin);
    let input_hash = sha256(input_bin);
    let output_hash = sha256(output_bin);

    if artifact.model_hash != model_hash
        || artifact.input_hash != input_hash
        || artifact.output_hash != output_hash
    {
        return Err(VerifaiError::HashMismatch);
    }

    let run = run_mlp_v1(model_bin, input_bin)?;
    let recomputed_output_bin = run.output.encode_bin();
    if sha256(&recomputed_output_bin) != output_hash {
        return Err(VerifaiError::HashMismatch);
    }

    let event_bytes: Vec<Vec<u8>> = run.events.iter().map(|e| e.encode_bin()).collect();
    let trace_root = trace_root_from_event_bytes(&event_bytes);

    if artifact.trace_root != trace_root {
        return Err(VerifaiError::TraceMismatch);
    }

    if artifact.attestation.measurement != trace_root {
        return Err(VerifaiError::TraceMismatch);
    }

    Ok(())
}

pub fn artifact_version(artifact_bin: &[u8]) -> Option<u16> {
    if artifact_bin.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([artifact_bin[0], artifact_bin[1]]))
}
