use assert_cmd::Command;
use assert_fs::fixture::PathChild;
use assert_fs::TempDir;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const KEY_HEX: &str = "0909090909090909090909090909090909090909090909090909090909090909";

fn tv_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .join(rel)
}

fn prove_artifacts(temp: &TempDir) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let output = temp.child("out.bin");
    let artifact = temp.child("artifact.bin");

    Command::cargo_bin("verifai-cli")?
        .args([
            "prove",
            "--model",
            tv_path("case-1/model.json").to_str().unwrap(),
            "--input",
            tv_path("case-1/input.json").to_str().unwrap(),
            "--out-output",
            output.path().to_str().unwrap(),
            "--out-artifact",
            artifact.path().to_str().unwrap(),
            "--key-hex",
            KEY_HEX,
        ])
        .assert()
        .success();

    Ok((output.path().to_path_buf(), artifact.path().to_path_buf()))
}

fn read_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let value = serde_json::from_str(contents.trim())?;
    Ok(value)
}

#[test]
fn prove_writes_json_file_when_requested() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let json_file = temp.child("prove.json");

    let output = temp.child("output.bin");
    let artifact = temp.child("artifact.bin");

    let output = Command::cargo_bin("verifai-cli")?
        .args([
            "prove",
            "--model",
            tv_path("case-1/model.json").to_str().unwrap(),
            "--input",
            tv_path("case-1/input.json").to_str().unwrap(),
            "--out-output",
            output.path().to_str().unwrap(),
            "--out-artifact",
            artifact.path().to_str().unwrap(),
            "--key-hex",
            KEY_HEX,
            "--json-file",
            json_file.path().to_str().unwrap(),
        ])
        .output()?;

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let value = read_json(json_file.path())?;
    assert_eq!(value["cmd"], "prove");
    Ok(())
}

#[test]
fn print_json_with_json_file_stays_silent() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let json_file = temp.child("prove.json");

    let output = temp.child("output.bin");
    let artifact = temp.child("artifact.bin");

    let output = Command::cargo_bin("verifai-cli")?
        .args([
            "prove",
            "--print-json",
            "--model",
            tv_path("case-1/model.json").to_str().unwrap(),
            "--input",
            tv_path("case-1/input.json").to_str().unwrap(),
            "--out-output",
            output.path().to_str().unwrap(),
            "--out-artifact",
            artifact.path().to_str().unwrap(),
            "--key-hex",
            KEY_HEX,
            "--json-file",
            json_file.path().to_str().unwrap(),
        ])
        .output()?;

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let value = read_json(json_file.path())?;
    assert_eq!(value["cmd"], "prove");
    Ok(())
}

#[test]
fn verify_writes_json_file() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (output_path, artifact_path) = prove_artifacts(&temp)?;
    let json_file = temp.child("verify.json");

    let output = Command::cargo_bin("verifai-cli")?
        .args([
            "verify",
            "--artifact",
            artifact_path.to_str().unwrap(),
            "--model",
            tv_path("case-1/model.json").to_str().unwrap(),
            "--input",
            tv_path("case-1/input.json").to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--json-file",
            json_file.path().to_str().unwrap(),
        ])
        .output()?;

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let value = read_json(json_file.path())?;
    assert_eq!(value["cmd"], "verify");
    Ok(())
}

#[test]
fn quiet_json_file_combination_still_writes() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (output_path, artifact_path) = prove_artifacts(&temp)?;
    let json_file = temp.child("verify.json");

    let output = Command::cargo_bin("verifai-cli")?
        .args([
            "--quiet",
            "verify",
            "--artifact",
            artifact_path.to_str().unwrap(),
            "--model",
            tv_path("case-1/model.json").to_str().unwrap(),
            "--input",
            tv_path("case-1/input.json").to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--json-file",
            json_file.path().to_str().unwrap(),
        ])
        .output()?;

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(json_file.path().exists());
    Ok(())
}
