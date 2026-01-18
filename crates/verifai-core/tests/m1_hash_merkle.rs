use verifai_core::hash::sha256;
use verifai_core::merkle::{empty_root, leaf_hash, node_hash, trace_root_from_event_bytes};

#[test]
fn test_sha256_domain_separation_leaf_vs_node() {
    let ev = b"abc";
    let leaf = leaf_hash(ev);

    let mut buf = Vec::new();
    buf.push(0x01);
    buf.extend_from_slice(&sha256(ev));
    buf.extend_from_slice(&sha256(ev));
    let node_like = sha256(&buf);

    assert_ne!(leaf, node_like);
}

#[test]
fn test_merkle_root_empty_is_fixed() {
    assert_eq!(empty_root(), sha256(&[0x02]));
}

#[test]
fn test_merkle_root_one_leaf() {
    let ev0 = vec![0xAA, 0xBB];
    let root = trace_root_from_event_bytes(&[ev0.clone()]);
    assert_eq!(root, leaf_hash(&ev0));
}

#[test]
fn test_merkle_root_two_leaves() {
    let ev0 = vec![0x00];
    let ev1 = vec![0x01, 0x02];

    let leaf0 = leaf_hash(&ev0);
    let leaf1 = leaf_hash(&ev1);
    let expected = node_hash(leaf0, leaf1);

    let root = trace_root_from_event_bytes(&[ev0, ev1]);
    assert_eq!(root, expected);
}

#[test]
fn test_merkle_root_odd_duplicates_last() {
    let ev0 = vec![0x10];
    let ev1 = vec![0x11];
    let ev2 = vec![0x12];

    let l0 = leaf_hash(&ev0);
    let l1 = leaf_hash(&ev1);
    let l2 = leaf_hash(&ev2);
    let p0 = node_hash(l0, l1);
    let p1 = node_hash(l2, l2);
    let expected = node_hash(p0, p1);

    let root = trace_root_from_event_bytes(&[ev0, ev1, ev2]);
    assert_eq!(root, expected);
}
