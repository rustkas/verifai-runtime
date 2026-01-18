use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use verifai_core::artifact_bin::ProofArtifactV0;
use verifai_core::hash::sha256;
use verifai_core::model_bin::{InputV0, LogisticModelV0};
use verifai_runtime::{prove_lr_v0, verify_lr_v0};

#[derive(Parser)]
#[command(name = "verifai")]
#[command(version)]
#[command(about = "Deterministic verifiable inference (MVP: logistic regression)")]
struct Cli {
    /// CI-friendly: no stdout on success (errors still go to stderr)
    #[arg(long, global = true)]
    quiet: bool,

    /// Print machine-readable JSON to stdout on success (suppressed by --quiet)
    #[arg(long, global = true)]
    print_json: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read model.json -> canonical model.bin, print SHA-256 hash of model.bin
    HashModel {
        /// Path to model.json
        #[arg(long)]
        model: PathBuf,

        /// Write canonical model.bin to this path (optional)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Read model.json + input.json -> run inference -> write output.bin + artifact.bin
    Prove {
        /// Path to model.json
        #[arg(long)]
        model: PathBuf,

        /// Path to input.json
        #[arg(long)]
        input: PathBuf,

        /// Output path for output.bin
        #[arg(long)]
        out_output: PathBuf,

        /// Output path for artifact.bin
        #[arg(long)]
        out_artifact: PathBuf,

        /// Optional: write canonical model.bin
        #[arg(long)]
        out_model_bin: Option<PathBuf>,

        /// Optional: write canonical input.bin
        #[arg(long)]
        out_input_bin: Option<PathBuf>,

        /// Signing key (Ed25519 secret key) as 64 hex chars (32 bytes)
        #[arg(long)]
        key_hex: String,

        /// Runtime id as 64 hex chars (32 bytes). If omitted, uses sha256("verifai-cli-default-runtime")
        #[arg(long)]
        runtime_id_hex: Option<String>,
    },

    /// Verify artifact.bin against model.json + input.json + output.bin
    Verify {
        /// Path to artifact.bin
        #[arg(long)]
        artifact: PathBuf,

        /// Path to model.json
        #[arg(long)]
        model: PathBuf,

        /// Path to input.json
        #[arg(long)]
        input: PathBuf,

        /// Path to output.bin
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code()
        }
    };

    process::exit(exit_code);
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.cmd {
        Command::HashModel { model, out } => {
            let model_v0 = read_model_json(&model)?;
            let model_bin = model_v0.encode_bin();
            let model_hash = sha256(&model_bin);

            if let Some(out_path) = &out {
                write_file_atomic(&out_path, &model_bin)?;
            }

            if !cli.quiet {
                if cli.print_json {
                    let payload = JsonOut::HashModel {
                        ok: true,
                        model_hash: hex_encode_32(model_hash),
                        out_model_bin: out.as_ref().map(|p| path_string_ref(p)),
                    };
                    print_json_line(&payload)?;
                } else {
                    println!("{}", hex_encode_32(model_hash));
                }
            }
            Ok(())
        }

        Command::Prove {
            model,
            input,
            out_output,
            out_artifact,
            out_model_bin,
            out_input_bin,
            key_hex,
            runtime_id_hex,
        } => {
            let model_v0 = read_model_json(&model)?;
            let input_v0 = read_input_json(&input)?;

            let model_bin = model_v0.encode_bin();
            let input_bin = input_v0.encode_bin();

            if let Some(p) = &out_model_bin {
                write_file_atomic(p, &model_bin)?;
            }
            if let Some(p) = &out_input_bin {
                write_file_atomic(p, &input_bin)?;
            }

            let signing_key = parse_hex_32(&key_hex)
                .map_err(|_| CliError::InvalidHex("key_hex must be 64 hex chars (32 bytes)"))?;

            let runtime_id = match runtime_id_hex {
                Some(s) => parse_hex_32(&s)
                    .map_err(|_| CliError::InvalidHex("runtime_id_hex must be 64 hex chars (32 bytes)"))?,
                None => sha256(b"verifai-cli-default-runtime"),
            };

            let (output_bin, artifact_bin) =
                prove_lr_v0(runtime_id, signing_key, &model_bin, &input_bin)
                    .map_err(|e| CliError::Runtime(format!("prove failed: {e:?}")))?;

            write_file_atomic(&out_output, &output_bin)?;
            write_file_atomic(&out_artifact, &artifact_bin)?;

            let artifact = ProofArtifactV0::decode_bin(&artifact_bin)
                .map_err(|_| CliError::Runtime("artifact decode failed".into()))?;

            let model_hash = sha256(&model_bin);
            let input_hash = sha256(&input_bin);
            let output_hash = sha256(&output_bin);

            if !cli.quiet {
                if cli.print_json {
                    let payload = JsonOut::Prove {
                        ok: true,
                        runtime_id: hex_encode_32(runtime_id),
                        model_hash: hex_encode_32(model_hash),
                        input_hash: hex_encode_32(input_hash),
                        output_hash: hex_encode_32(output_hash),
                        trace_root: hex_encode_32(artifact.trace_root),
                        sig_pubkey: hex_encode_32(artifact.sig_pubkey),
                        out_model_bin: out_model_bin.as_ref().map(|p| path_string_ref(p)),
                        out_input_bin: out_input_bin.as_ref().map(|p| path_string_ref(p)),
                        out_output: path_string(out_output),
                        out_artifact: path_string(out_artifact),
                    };
                    print_json_line(&payload)?;
                } else {
                    println!("ok");
                    println!("model_hash  : {}", hex_encode_32(model_hash));
                    println!("input_hash  : {}", hex_encode_32(input_hash));
                    println!("output_hash : {}", hex_encode_32(output_hash));
                    println!("runtime_id  : {}", hex_encode_32(runtime_id));
                    println!("trace_root  : {}", hex_encode_32(artifact.trace_root));
                    println!("sig_pubkey  : {}", hex_encode_32(artifact.sig_pubkey));
                }
            }

            Ok(())
        }

        Command::Verify {
            artifact,
            model,
            input,
            output,
        } => {
            let artifact_bin = read_file(&artifact)?;
            let model_v0 = read_model_json(&model)?;
            let input_v0 = read_input_json(&input)?;
            let output_bin = read_file(&output)?;

            let model_bin = model_v0.encode_bin();
            let input_bin = input_v0.encode_bin();

            verify_lr_v0(&artifact_bin, &model_bin, &input_bin, &output_bin)
                .map_err(|e| CliError::VerifyFailed(format!("{e:?}")))?;

            let a = ProofArtifactV0::decode_bin(&artifact_bin)
                .map_err(|_| CliError::VerifyFailed("artifact decode failed".into()))?;

            if !cli.quiet {
                if cli.print_json {
                    let payload = JsonOut::Verify {
                        ok: true,
                        trace_root: hex_encode_32(a.trace_root),
                        sig_pubkey: hex_encode_32(a.sig_pubkey),
                        artifact: path_string(artifact),
                        model: path_string(model),
                        input: path_string(input),
                        output: path_string(output),
                    };
                    print_json_line(&payload)?;
                } else {
                    println!("ok");
                    println!("trace_root : {}", hex_encode_32(a.trace_root));
                    println!("sig_pubkey : {}", hex_encode_32(a.sig_pubkey));
                }
            }

            Ok(())
        }
    }
}

/* ----------------------------- JSON output ----------------------------- */

#[derive(serde::Serialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
enum JsonOut {
    HashModel {
        ok: bool,
        model_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        out_model_bin: Option<String>,
    },
    Prove {
        ok: bool,
        runtime_id: String,
        model_hash: String,
        input_hash: String,
        output_hash: String,
        trace_root: String,
        sig_pubkey: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        out_model_bin: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        out_input_bin: Option<String>,
        out_output: String,
        out_artifact: String,
    },
    Verify {
        ok: bool,
        trace_root: String,
        sig_pubkey: String,
        artifact: String,
        model: String,
        input: String,
        output: String,
    },
}

fn print_json_line(payload: &JsonOut) -> Result<(), CliError> {
    let s = serde_json::to_string(payload).map_err(|e| CliError::Json(format!("{e}")))?;
    println!("{s}");
    Ok(())
}

fn path_string(p: PathBuf) -> String {
    path_string_ref(&p)
}

fn path_string_ref(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/* ----------------------------- JSON parsing ----------------------------- */

#[derive(Debug, Deserialize)]
struct ModelJsonV0 {
    weights: Vec<f64>,
    bias: f64,
}

#[derive(Debug, Deserialize)]
struct InputJsonV0 {
    x: Vec<f64>,
}

fn read_model_json(path: &PathBuf) -> Result<LogisticModelV0, CliError> {
    let bytes = read_file(path)?;
    let parsed: ModelJsonV0 =
        serde_json::from_slice(&bytes).map_err(|e| CliError::Json(format!("{e}")))?;
    Ok(LogisticModelV0 {
        weights: parsed.weights,
        bias: parsed.bias,
    })
}

fn read_input_json(path: &PathBuf) -> Result<InputV0, CliError> {
    let bytes = read_file(path)?;
    let parsed: InputJsonV0 =
        serde_json::from_slice(&bytes).map_err(|e| CliError::Json(format!("{e}")))?;
    Ok(InputV0 { x: parsed.x })
}

/* ----------------------------- IO helpers ----------------------------- */

fn read_file(path: &PathBuf) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

fn write_file_atomic(path: &PathBuf, data: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or(CliError::Io(format!("invalid output path: {}", path.display())))?
        .to_string_lossy();

    let tmp_path = parent.join(format!(".{}.tmp", file_name));
    fs::write(&tmp_path, data)
        .map_err(|e| CliError::Io(format!("{}: {e}", tmp_path.display())))?;

    fs::rename(&tmp_path, path)
        .map_err(|e| CliError::Io(format!("{}: {e}", path.display())))?;

    Ok(())
}

/* ----------------------------- Hex helpers ----------------------------- */

fn parse_hex_32(s: &str) -> Result<[u8; 32], ()> {
    let bytes = hex_decode_exact(s, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_decode_exact(s: &str, expected_len: usize) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if s.len() != expected_len * 2 {
        return Err(());
    }
    let mut out = Vec::with_capacity(expected_len);
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + (c - b'a')),
        b'A'..=b'F' => Ok(10 + (c - b'A')),
        _ => Err(()),
    }
}

fn hex_encode_32(x: [u8; 32]) -> String {
    hex_encode(&x)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize]);
        out.push(LUT[(b & 0x0F) as usize]);
    }
    String::from_utf8(out).expect("hex is valid utf-8")
}

/* ------------------------------ Errors -------------------------------- */

#[derive(Debug)]
enum CliError {
    Io(String),
    Json(String),
    InvalidHex(&'static str),
    Runtime(String),
    VerifyFailed(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            CliError::Io(_) => 2,
            CliError::Json(_) => 3,
            CliError::InvalidHex(_) => 4,
            CliError::Runtime(_) => 5,
            CliError::VerifyFailed(_) => 6,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(s) => write!(f, "io: {s}"),
            CliError::Json(s) => write!(f, "json: {s}"),
            CliError::InvalidHex(s) => write!(f, "hex: {s}"),
            CliError::Runtime(s) => write!(f, "{s}"),
            CliError::VerifyFailed(s) => write!(f, "verify failed: {s}"),
        }
    }
}
