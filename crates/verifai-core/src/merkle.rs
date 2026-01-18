use crate::hash::sha256;

pub fn leaf_hash(event_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + event_bytes.len());
    buf.push(0x00);
    buf.extend_from_slice(event_bytes);
    sha256(&buf)
}

pub fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(0x01);
    buf.extend_from_slice(&left);
    buf.extend_from_slice(&right);
    sha256(&buf)
}

pub fn empty_root() -> [u8; 32] {
    sha256(&[0x02])
}

pub fn trace_root_from_event_bytes(events: &[Vec<u8>]) -> [u8; 32] {
    if events.is_empty() {
        return empty_root();
    }

    let mut level: Vec<[u8; 32]> = events.iter().map(|e| leaf_hash(e)).collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(node_hash(pair[0], pair[1]));
        }
        level = next;
    }

    level[0]
}
