use verifai_core::model_bin::{InputV0, LogisticModelV0, OutputV0};
use verifai_runtime::{prove_lr_v0, verify_lr_v0};

#[test]
fn test_verify_rejects_modified_output() {
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

    let (mut out_bin, art) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    out_bin[8] ^= 0x01;

    assert!(verify_lr_v0(&art, &model_bin, &input_bin, &out_bin).is_err());
}

#[test]
fn test_verify_rejects_modified_input() {
    let model = LogisticModelV0 {
        weights: vec![0.1, -0.2, 0.3, 0.4],
        bias: -0.05,
    };
    let input = InputV0 {
        x: vec![1.0, 2.0, 3.0, 4.0],
    };

    let model_bin = model.encode_bin();
    let mut input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (out_bin, art) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    input_bin[12] ^= 0x01;

    assert!(verify_lr_v0(&art, &model_bin, &input_bin, &out_bin).is_err());
}

#[test]
fn test_verify_rejects_modified_model() {
    let mut model = LogisticModelV0 {
        weights: vec![0.1, -0.2, 0.3, 0.4],
        bias: -0.05,
    };
    let input = InputV0 {
        x: vec![1.0, 2.0, 3.0, 4.0],
    };

    let mut model_bin = model.encode_bin();
    let input_bin = input.encode_bin();

    let runtime_id = [7u8; 32];
    let sk = [9u8; 32];

    let (out_bin, art) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    model_bin[12] ^= 0x01;

    assert!(verify_lr_v0(&art, &model_bin, &input_bin, &out_bin).is_err());

    model.bias += 0.0;
}

#[test]
fn test_verify_rejects_modified_trace_by_artifact_tamper() {
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

    let (out_bin, mut art) = prove_lr_v0(runtime_id, sk, &model_bin, &input_bin).unwrap();

    art[130] ^= 0x01;

    assert!(verify_lr_v0(&art, &model_bin, &input_bin, &out_bin).is_err());
}

#[test]
fn test_output_bin_roundtrip_smoke() {
    let out = OutputV0 { y: 0.5 };
    let bin = out.encode_bin();
    let back = OutputV0::decode_bin(&bin).unwrap();
    assert_eq!(out, back);
}
