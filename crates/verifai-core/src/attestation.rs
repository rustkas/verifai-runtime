use crate::bytes::{push_bytes, push_u32_le, BytesError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBundle {
    pub attester_id: [u8; 32],
    pub measurement: [u8; 32],
    pub attestation: Vec<u8>,
}

impl AttestationBundle {
    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4 + self.attestation.len());
        push_bytes(&mut out, &self.attester_id);
        push_bytes(&mut out, &self.measurement);
        push_u32_le(&mut out, self.attestation.len() as u32);
        push_bytes(&mut out, &self.attestation);
        out
    }

    pub fn decode_bin(buf: &[u8]) -> Result<Self, BytesError> {
        let mut r = Reader::new(buf);
        let attester_id = read_32(&mut r)?;
        let measurement = read_32(&mut r)?;
        let att_len = r.read_u32_le()? as usize;
        let attestation = r.read_exact(att_len)?.to_vec();
        if r.remaining() != 0 {
            return Err(BytesError::InvalidLength);
        }
        Ok(Self {
            attester_id,
            measurement,
            attestation,
        })
    }
}

fn read_32(r: &mut Reader<'_>) -> Result<[u8; 32], BytesError> {
    let b = r.read_exact(32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}
