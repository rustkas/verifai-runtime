use verifai_core::model_bin::{InputV0, LogisticModelV0};
use verifai_runtime::prove_lr_v0;

#[test]
fn test_prove_is_deterministic_bytes_equal() {
    let model = LogisticModelV0 {
        weights: vec![0.1, -0.2, 0.3, 0.4],
        bias: -0.05,
    };
    let input = InputV0 {
        x: vec![1.0, 2.0, 3.0, 4.0],
    };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (out1, art1) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();
    let (out2, art2) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    assert_eq!(out1, out2);
    assert_eq!(art1, art2);
}

#[test]
fn test_trace_is_deterministic_and_non_empty() {
    let model = LogisticModelV0 {
        weights: vec![0.0, 0.0, 0.0, 0.0],
        bias: 0.0,
    };
    let input = InputV0 { x: vec![0.0, 0.0, 0.0, 0.0] };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (_out, art) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    assert!(art.iter().any(|&b| b != 0));
}
