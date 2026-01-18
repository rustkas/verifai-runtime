use proptest::collection;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use verifai_core::artifact_bin::ProofArtifactV0;
use verifai_core::merkle::trace_root_from_event_bytes;

#[test]
fn decode_bin_handles_random_bytes() {
    let mut runner = TestRunner::new(ProptestConfig::with_cases(64));
    runner
        .run(&collection::vec(any::<u8>(), 0..512), |bytes| {
            let _ = ProofArtifactV0::decode_bin(&bytes);
            Ok(())
        })
        .expect("decode should never panic");
}

#[test]
fn merkle_root_changes_when_leaf_mutated() {
    let mut runner = TestRunner::new(ProptestConfig::with_cases(64));
    runner
        .run(
            &collection::vec(collection::vec(any::<u8>(), 1..8), 1..4),
            |mut events| {
                let root = trace_root_from_event_bytes(&events);
                events[0][0] ^= 0xFF;
                let mutated = trace_root_from_event_bytes(&events);
                prop_assert_ne!(root, mutated);
                Ok(())
            },
        )
        .expect("mutating event should change merkle root");
}
