use std::fs;
use std::path::Path;

use verifai_core::model_bin::{InputV0, MlpModelV1};
use verifai_runtime::prove_mlp_v1;

fn main() {
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

    let (output_bin, artifact_bin) = prove_mlp_v1(runtime_id, sk, &model_bin, &input_bin).unwrap();

    let dir = Path::new("test-vectors/mlp-case-1");
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("model.bin"), model_bin).unwrap();
    fs::write(dir.join("input.bin"), input_bin).unwrap();
    fs::write(dir.join("expected_output.bin"), output_bin).unwrap();
    fs::write(dir.join("expected_artifact.bin"), artifact_bin).unwrap();
}
