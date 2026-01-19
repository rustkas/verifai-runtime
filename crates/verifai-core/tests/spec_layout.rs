use verifai_core::artifact_bin::ProofArtifactV1;
use verifai_core::artifact_bin::{ProofArtifactV0, PROOF_ARTIFACT_V0_LEN};
use verifai_core::attestation::AttestationBundle;
use verifai_core::model_bin::{InputV0, LogisticModelV0, OutputV0};

fn sample_artifact() -> ProofArtifactV0 {
    ProofArtifactV0 {
        version: 0,
        runtime_id: [1u8; 32],
        model_hash: [2u8; 32],
        input_hash: [3u8; 32],
        output_hash: [4u8; 32],
        trace_root: [5u8; 32],
        sig_pubkey: [6u8; 32],
        signature: [7u8; 64],
    }
}

#[test]
fn proof_artifact_layout_matches_spec_offsets() {
    let artifact = sample_artifact();
    let bin = artifact.encode_bin();
    assert_eq!(bin.len(), PROOF_ARTIFACT_V0_LEN);

    let version = u16::from_le_bytes([bin[0], bin[1]]);
    assert_eq!(version, artifact.version);

    assert_eq!(&bin[2..34], &artifact.runtime_id);
    assert_eq!(&bin[34..66], &artifact.model_hash);
    assert_eq!(&bin[66..98], &artifact.input_hash);
    assert_eq!(&bin[98..130], &artifact.output_hash);
    assert_eq!(&bin[130..162], &artifact.trace_root);
    assert_eq!(&bin[162..194], &artifact.sig_pubkey);
    assert_eq!(&bin[194..258], &artifact.signature);
}

#[test]
fn proof_artifact_encode_decode_is_canonical() {
    let artifact = sample_artifact();
    let encoded = artifact.encode_bin();
    let decoded = ProofArtifactV0::decode_bin(&encoded).expect("decode should work");
    assert_eq!(decoded, artifact);
    assert_eq!(encoded, decoded.encode_bin());
}

#[test]
fn model_input_output_layout_and_roundtrip() {
    let model = LogisticModelV0 {
        weights: vec![0.1, -0.2, 0.3],
        bias: 1.5,
    };
    let input = InputV0 {
        x: vec![1.0, 2.0, 3.0],
    };
    let output = OutputV0 { y: 0.25 };

    let model_bin = model.encode_bin();
    assert_eq!(&model_bin[0..8], b"VFAIMDL0");
    let len = u32::from_le_bytes(model_bin[8..12].try_into().unwrap()) as usize;
    assert_eq!(len, 3);
    assert_eq!(model_bin.len(), 12 + len * 8 + 8);

    let input_bin = input.encode_bin();
    assert_eq!(&input_bin[0..8], b"VFAIINP0");
    let input_len = u32::from_le_bytes(input_bin[8..12].try_into().unwrap()) as usize;
    assert_eq!(input_len, 3);
    assert_eq!(input_bin.len(), 12 + input_len * 8);

    let output_bin = output.encode_bin();
    assert_eq!(&output_bin[0..8], b"VFAIOUT0");
    assert_eq!(output_bin.len(), 16);

    let model_decoded = LogisticModelV0::decode_bin(&model_bin).expect("decode model");
    assert_eq!(model_decoded, model);
    assert_eq!(model_bin, model_decoded.encode_bin());

    let input_decoded = InputV0::decode_bin(&input_bin).expect("decode input");
    assert_eq!(input_decoded, input);
    assert_eq!(input_bin, input_decoded.encode_bin());

    let output_decoded = OutputV0::decode_bin(&output_bin).expect("decode output");
    assert_eq!(output_decoded, output);
    assert_eq!(output_bin, output_decoded.encode_bin());
}

#[test]
fn proof_artifact_v1_layout_and_roundtrip() {
    let att = AttestationBundle {
        attester_id: [9u8; 32],
        measurement: [8u8; 32],
        attestation: vec![1, 2, 3],
    };
    let artifact = ProofArtifactV1 {
        version: 1,
        runtime_id: [1u8; 32],
        model_hash: [2u8; 32],
        input_hash: [3u8; 32],
        output_hash: [4u8; 32],
        trace_root: [5u8; 32],
        sig_pubkey: [6u8; 32],
        signature: [7u8; 64],
        attestation: att.clone(),
    };
    let encoded = artifact.encode_bin();
    assert_eq!(encoded.len(), 2 + 32 * 6 + 64 + att.encode_bin().len());
    let decoded = ProofArtifactV1::decode_bin(&encoded).expect("decode v1");
    assert_eq!(decoded, artifact);
}
