use crate::attestation::AttestationBundle;
use crate::bytes::{push_bytes, push_u16_le, BytesError, Reader};
use crate::hash::sha256;

use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub const PROOF_ARTIFACT_V0_LEN: usize = 258;

const SIGN_PREFIX: &[u8; 19] = b"VERIFAI\0ARTIFACT\0V0";
const SIGN_PREFIX_V1: &[u8; 19] = b"VERIFAI\0ARTIFACT\0V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofArtifactV0 {
    pub version: u16, // must be 0 for v0
    pub runtime_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub trace_root: [u8; 32],
    pub sig_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofArtifactV1 {
    pub version: u16,
    pub runtime_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub trace_root: [u8; 32],
    pub sig_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub attestation: AttestationBundle,
}

impl ProofArtifactV0 {
    pub fn message_to_sign(&self) -> Vec<u8> {
        // prefix + (all fields except signature), including sig_pubkey
        let mut out = Vec::with_capacity(19 + 2 + 32 * 6);
        out.extend_from_slice(SIGN_PREFIX);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.runtime_id);
        out.extend_from_slice(&self.model_hash);
        out.extend_from_slice(&self.input_hash);
        out.extend_from_slice(&self.output_hash);
        out.extend_from_slice(&self.trace_root);
        out.extend_from_slice(&self.sig_pubkey);
        out
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_ARTIFACT_V0_LEN);
        push_u16_le(&mut out, self.version);
        push_bytes(&mut out, &self.runtime_id);
        push_bytes(&mut out, &self.model_hash);
        push_bytes(&mut out, &self.input_hash);
        push_bytes(&mut out, &self.output_hash);
        push_bytes(&mut out, &self.trace_root);
        push_bytes(&mut out, &self.sig_pubkey);
        push_bytes(&mut out, &self.signature);
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        if buf.len() != PROOF_ARTIFACT_V0_LEN {
            return Err(BytesError::InvalidLength);
        }
        let mut r = Reader::new(buf);
        let version = r.read_u16_le()?;
        let runtime_id = read_32(&mut r)?;
        let model_hash = read_32(&mut r)?;
        let input_hash = read_32(&mut r)?;
        let output_hash = read_32(&mut r)?;
        let trace_root = read_32(&mut r)?;
        let sig_pubkey = read_32(&mut r)?;
        let signature = read_64(&mut r)?;
        Ok(Self {
            version,
            runtime_id,
            model_hash,
            input_hash,
            output_hash,
            trace_root,
            sig_pubkey,
            signature,
        })
    }

    pub fn sign_detached(&mut self, signing_key_bytes: [u8; 32]) -> Result<(), BytesError> {
        let sk = SigningKey::from_bytes(&signing_key_bytes);
        let vk = VerifyingKey::from(&sk);
        self.sig_pubkey = vk.to_bytes();

        let msg = self.message_to_sign();
        let sig: Signature = sk.sign(&msg);
        self.signature = sig.to_bytes();
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), BytesError> {
        let vk =
            VerifyingKey::from_bytes(&self.sig_pubkey).map_err(|_| BytesError::InvalidLength)?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = self.message_to_sign();
        vk.verify(&msg, &sig)
            .map_err(|_| BytesError::InvalidLength)?;
        Ok(())
    }

    pub fn runtime_id_from_bytes(runtime_bytes: &[u8]) -> [u8; 32] {
        // convenience helper: deterministic runtime_id if you want one
        sha256(runtime_bytes)
    }
}

impl ProofArtifactV1 {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(19 + 2 + 32 * 6 + self.attestation.encode_bin().len());
        out.extend_from_slice(SIGN_PREFIX_V1);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.runtime_id);
        out.extend_from_slice(&self.model_hash);
        out.extend_from_slice(&self.input_hash);
        out.extend_from_slice(&self.output_hash);
        out.extend_from_slice(&self.trace_root);
        out.extend_from_slice(&self.sig_pubkey);
        out.extend_from_slice(&self.attestation.encode_bin());
        out
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(19 + 2 + 32 * 6 + self.attestation.encode_bin().len());
        push_u16_le(&mut out, self.version);
        push_bytes(&mut out, &self.runtime_id);
        push_bytes(&mut out, &self.model_hash);
        push_bytes(&mut out, &self.input_hash);
        push_bytes(&mut out, &self.output_hash);
        push_bytes(&mut out, &self.trace_root);
        push_bytes(&mut out, &self.sig_pubkey);
        push_bytes(&mut out, &self.signature);
        push_bytes(&mut out, &self.attestation.encode_bin());
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let version = r.read_u16_le()?;
        if version != 1 {
            return Err(BytesError::InvalidLength);
        }
        let runtime_id = read_32(&mut r)?;
        let model_hash = read_32(&mut r)?;
        let input_hash = read_32(&mut r)?;
        let output_hash = read_32(&mut r)?;
        let trace_root = read_32(&mut r)?;
        let sig_pubkey = read_32(&mut r)?;
        let signature = read_64(&mut r)?;
        let remaining = r.read_exact(r.remaining())?;
        let attestation = AttestationBundle::decode_bin(remaining)?;
        Ok(Self {
            version,
            runtime_id,
            model_hash,
            input_hash,
            output_hash,
            trace_root,
            sig_pubkey,
            signature,
            attestation,
        })
    }

    pub fn sign_detached(&mut self, signing_key_bytes: [u8; 32]) -> Result<(), BytesError> {
        let sk = SigningKey::from_bytes(&signing_key_bytes);
        let vk = VerifyingKey::from(&sk);
        self.sig_pubkey = vk.to_bytes();

        let msg = self.message_to_sign();
        let sig: Signature = sk.sign(&msg);
        self.signature = sig.to_bytes();
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), BytesError> {
        let vk =
            VerifyingKey::from_bytes(&self.sig_pubkey).map_err(|_| BytesError::InvalidLength)?;
        let sig = Signature::from_bytes(&self.signature);
        let msg = self.message_to_sign();
        vk.verify(&msg, &sig)
            .map_err(|_| BytesError::InvalidLength)?;
        Ok(())
    }
}

fn read_32(r: &mut Reader<'_>) -> Result<[u8; 32], BytesError> {
    let b = r.read_exact(32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

fn read_64(r: &mut Reader<'_>) -> Result<[u8; 64], BytesError> {
    let b = r.read_exact(64)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(b);
    Ok(out)
}
