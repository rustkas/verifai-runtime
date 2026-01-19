use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use verifai_core::model_bin::{InputV0, LogisticModelV0, MlpModelV1};
use verifai_runtime::{prove_lr_v0, prove_mlp_v1, VerifaiError};

const RUNTIME_ID: [u8; 32] = [7u8; 32];
const SIGNING_KEY: [u8; 32] = [9u8; 32];

#[derive(Deserialize)]
struct LogisticModelJson {
    weights: Vec<f64>,
    bias: f64,
}

#[derive(Deserialize)]
struct InputJson {
    x: Vec<f64>,
}

#[derive(Deserialize)]
struct MlpModelJson {
    input_dim: u32,
    hidden_size: u32,
    w1: Vec<f64>,
    b1: Vec<f64>,
    w2: Vec<f64>,
    b2: f64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new("test-vectors");
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if name.starts_with("case-") {
            update_logistic_case(&path)?;
        } else if name.starts_with("mlp-") {
            update_mlp_case(&path)?;
        }
    }

    Ok(())
}

fn update_logistic_case(dir: &Path) -> Result<(), Box<dyn Error>> {
    println!("Updating logistic test vector {}", dir.display());
    let model_json = read_json::<LogisticModelJson>(&dir.join("model.json"))?;
    let input_json = read_json::<InputJson>(&dir.join("input.json"))?;

    let model = LogisticModelV0 {
        weights: model_json.weights,
        bias: model_json.bias,
    };
    let input = InputV0 { x: input_json.x };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();
    let (output_bin, artifact_bin) =
        match prove_lr_v0(RUNTIME_ID, SIGNING_KEY, &model_bin, &input_bin) {
            Ok(res) => res,
            Err(e) => return Err(Box::new(UpdateError(e))),
        };

    fs::write(dir.join("model.bin"), &model_bin)?;
    fs::write(dir.join("input.bin"), &input_bin)?;
    fs::write(dir.join("expected_output.bin"), &output_bin)?;
    fs::write(dir.join("expected_artifact.bin"), &artifact_bin)?;
    Ok(())
}

fn update_mlp_case(dir: &Path) -> Result<(), Box<dyn Error>> {
    println!("Updating MLP test vector {}", dir.display());
    let model_json = read_json::<MlpModelJson>(&dir.join("model.json"))?;
    let input_json = read_json::<InputJson>(&dir.join("input.json"))?;

    let model = MlpModelV1 {
        input_dim: model_json.input_dim,
        hidden_size: model_json.hidden_size,
        w1: model_json.w1,
        b1: model_json.b1,
        w2: model_json.w2,
        b2: model_json.b2,
    };
    let input = InputV0 { x: input_json.x };

    let model_bin = model.encode_bin();
    let input_bin = input.encode_bin();
    let (output_bin, artifact_bin) =
        match prove_mlp_v1(RUNTIME_ID, SIGNING_KEY, &model_bin, &input_bin) {
            Ok(res) => res,
            Err(e) => return Err(Box::new(UpdateError(e))),
        };

    fs::write(dir.join("model.bin"), &model_bin)?;
    fs::write(dir.join("input.bin"), &input_bin)?;
    fs::write(dir.join("expected_output.bin"), &output_bin)?;
    fs::write(dir.join("expected_artifact.bin"), &artifact_bin)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let parsed = serde_json::from_slice(&bytes)?;
    Ok(parsed)
}

#[derive(Debug)]
struct UpdateError(VerifaiError);

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "update failed: {:?}", self.0)
    }
}

impl Error for UpdateError {}
