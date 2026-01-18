use crate::bytes::{push_bytes, push_f64_le, push_u32_le, Reader, BytesError};

const MODEL_MAGIC: &[u8; 8] = b"VFAIMDL0";
const INPUT_MAGIC: &[u8; 8] = b"VFAIINP0";
const OUTPUT_MAGIC: &[u8; 8] = b"VFAIOUT0";

#[derive(Debug, Clone, PartialEq)]
pub struct LogisticModelV0 {
    pub weights: Vec<f64>,
    pub bias: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InputV0 {
    pub x: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputV0 {
    pub y: f64,
}

impl LogisticModelV0 {
    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.weights.len() * 8 + 8);
        push_bytes(&mut out, MODEL_MAGIC);
        push_u32_le(&mut out, self.weights.len() as u32);
        for &w in &self.weights {
            push_f64_le(&mut out, w);
        }
        push_f64_le(&mut out, self.bias);
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let magic = r.read_exact(8)?;
        if magic != MODEL_MAGIC {
            return Err(BytesError::InvalidMagic);
        }
        let n = r.read_u32_le()? as usize;
        let mut weights = Vec::with_capacity(n);
        for _ in 0..n {
            weights.push(r.read_f64_le()?);
        }
        let bias = r.read_f64_le()?;
        if r.remaining() != 0 {
            // strict: no trailing bytes
            return Err(BytesError::InvalidLength);
        }
        Ok(Self { weights, bias })
    }
}

impl InputV0 {
    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.x.len() * 8);
        push_bytes(&mut out, INPUT_MAGIC);
        push_u32_le(&mut out, self.x.len() as u32);
        for &v in &self.x {
            push_f64_le(&mut out, v);
        }
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let magic = r.read_exact(8)?;
        if magic != INPUT_MAGIC {
            return Err(BytesError::InvalidMagic);
        }
        let n = r.read_u32_le()? as usize;
        let mut x = Vec::with_capacity(n);
        for _ in 0..n {
            x.push(r.read_f64_le()?);
        }
        if r.remaining() != 0 {
            return Err(BytesError::InvalidLength);
        }
        Ok(Self { x })
    }
}

impl OutputV0 {
    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        push_bytes(&mut out, OUTPUT_MAGIC);
        push_f64_le(&mut out, self.y);
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let magic = r.read_exact(8)?;
        if magic != OUTPUT_MAGIC {
            return Err(BytesError::InvalidMagic);
        }
        let y = r.read_f64_le()?;
        if r.remaining() != 0 {
            return Err(BytesError::InvalidLength);
        }
        Ok(Self { y })
    }
}
