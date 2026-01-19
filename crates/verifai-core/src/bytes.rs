#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BytesError {
    UnexpectedEof,
    InvalidMagic,
    InvalidLength,
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], BytesError> {
        if self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .is_none()
        {
            return Err(BytesError::UnexpectedEof);
        }
        let start = self.pos;
        let end = self.pos + n;
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    pub fn read_u8(&mut self) -> Result<u8, BytesError> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16, BytesError> {
        let b = self.read_exact(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, BytesError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_f64_le(&mut self) -> Result<f64, BytesError> {
        let b = self.read_exact(8)?;
        Ok(f64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

pub fn push_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn push_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn push_f64_le(out: &mut Vec<u8>, v: f64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn push_bytes(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(v);
}
