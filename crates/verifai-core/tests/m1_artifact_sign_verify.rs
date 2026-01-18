use verifai_core::artifact_bin::{ProofArtifactV0, PROOF_ARTIFACT_V0_LEN};

#[test]
fn test_artifact_encode_has_fixed_length_258() {
    let a = ProofArtifactV0 {
        version: 0,
        runtime_id: [1u8; 32],
        model_hash: [2u8; 32],
        input_hash: [3u8; 32],
        output_hash: [4u8; 32],
        trace_root: [5u8; 32],
        sig_pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    let b = a.encode_bin();
    assert_eq!(b.len(), PROOF_ARTIFACT_V0_LEN);
}

#[test]
fn test_artifact_sign_and_verify_ok() {
    let sk = [9u8; 32];

    let mut a = ProofArtifactV0 {
        version: 0,
        runtime_id: [1u8; 32],
        model_hash: [2u8; 32],
        input_hash: [3u8; 32],
        output_hash: [4u8; 32],
        trace_root: [5u8; 32],
        sig_pubkey: [0u8; 32],
        signature: [0u8; 64],
    };

    a.sign_detached(sk).unwrap();
    a.verify_signature().unwrap();
}

#[test]
fn test_artifact_verify_rejects_modified_field() {
    let sk = [9u8; 32];

    let mut a = ProofArtifactV0 {
        version: 0,
        runtime_id: [1u8; 32],
        model_hash: [2u8; 32],
        input_hash: [3u8; 32],
        output_hash: [4u8; 32],
        trace_root: [5u8; 32],
        sig_pubkey: [0u8; 32],
        signature: [0u8; 64],
    };

    a.sign_detached(sk).unwrap();

    let mut b = a.clone();
    b.output_hash[0] ^= 0xFF;

    assert!(b.verify_signature().is_err());
}
