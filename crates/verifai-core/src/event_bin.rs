use crate::bytes::{push_bytes, push_f64_le, push_u32_le, push_u8, BytesError, Reader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationKind {
    Sigmoid = 1,
    Relu = 2,
}

impl ActivationKind {
    fn from_u8(v: u8) -> Result<Self, BytesError> {
        match v {
            1 => Ok(Self::Sigmoid),
            2 => Ok(Self::Relu),
            _ => Err(BytesError::InvalidLength),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TraceEventV0 {
    OpLinear {
        op_id: u32,
        z: f64,
    },
    OpActivation {
        op_id: u32,
        kind: ActivationKind,
        input: f64,
        output: f64,
    },
    OpOutput {
        y: f64,
    },
}

impl TraceEventV0 {
    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match *self {
            Self::OpLinear { op_id, z } => {
                push_u8(&mut out, 0x01);
                push_u32_le(&mut out, op_id);
                push_f64_le(&mut out, z);
            }
            Self::OpActivation {
                op_id,
                kind,
                input,
                output,
            } => {
                push_u8(&mut out, 0x02);
                push_u32_le(&mut out, op_id);
                push_u8(&mut out, kind as u8);
                push_f64_le(&mut out, input);
                push_f64_le(&mut out, output);
            }
            Self::OpOutput { y } => {
                push_u8(&mut out, 0x03);
                push_f64_le(&mut out, y);
            }
        }
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let tag = r.read_u8()?;
        let ev = match tag {
            0x01 => {
                let op_id = r.read_u32_le()?;
                let z = r.read_f64_le()?;
                Self::OpLinear { op_id, z }
            }
            0x02 => {
                let op_id = r.read_u32_le()?;
                let kind = ActivationKind::from_u8(r.read_u8()?)?;
                let input = r.read_f64_le()?;
                let output = r.read_f64_le()?;
                Self::OpActivation {
                    op_id,
                    kind,
                    input,
                    output,
                }
            }
            0x03 => {
                let y = r.read_f64_le()?;
                Self::OpOutput { y }
            }
            _ => return Err(BytesError::InvalidLength),
        };
        if r.remaining() != 0 {
            return Err(BytesError::InvalidLength);
        }
        Ok(ev)
    }
}

// Small helper for fixed-size magic writes (keeps unused warnings away)
pub fn encode_magic(magic: &[u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    push_bytes(&mut out, magic);
    out
}
