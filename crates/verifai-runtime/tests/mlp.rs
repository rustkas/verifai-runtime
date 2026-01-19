use verifai_core::model_bin::{InputV0, MlpModelV1};
use verifai_runtime::{prove_mlp_v1, verify_mlp_v1};

#[test]
fn test_mlp_prove_is_deterministic() {
    let model = MlpModelV1 {
        input_dim: 4,
        hidden_size: 2,
        w1: vec![
            0.1, -0.2, 0.3, 0.4, // neuron 0
            -0.1, 0.5, 0.2, -0.3, // neuron 1
        ],
        b1: vec![0.0, -0.1],
        w2: vec![0.2, -0.4],
        b2: 0.05,
    };
    let input = InputV0 {
        x: vec![1.0, 0.5, -0.5, 0.25],
    };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (out1, art1) = prove_mlp_v1(runtime_id, sk, &model_bin, &input_bin).unwrap();
    let (out2, art2) = prove_mlp_v1(runtime_id, sk, &model_bin, &input_bin).unwrap();

    assert_eq!(out1, out2);
    assert_eq!(art1, art2);
}

#[test]
fn test_mlp_verify_detects_tamper() {
    let model = MlpModelV1 {
        input_dim: 4,
        hidden_size: 2,
        w1: vec![0.1, -0.2, 0.3, 0.4, -0.1, 0.5, 0.2, -0.3],
        b1: vec![0.0, -0.1],
        w2: vec![0.2, -0.4],
        b2: 0.05,
    };
    let input = InputV0 {
        x: vec![1.0, 0.5, -0.5, 0.25],
    };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (output_bin, mut artifact_bin) =
        prove_mlp_v1(runtime_id, sk, &model_bin, &input_bin).unwrap();

    artifact_bin[4] ^= 0x01;

    assert!(verify_mlp_v1(&artifact_bin, &model_bin, &input_bin, &output_bin).is_err());
}
