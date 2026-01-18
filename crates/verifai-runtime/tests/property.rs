use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use verifai_core::artifact_bin::PROOF_ARTIFACT_V0_LEN;
use verifai_core::model_bin::{InputV0, LogisticModelV0};
use verifai_runtime::{prove_lr_v0, verify_lr_v0};

#[test]
fn verify_rejects_one_byte_flips() {
    let mut runner = TestRunner::new(ProptestConfig::with_cases(64));
    runner
        .run(&(0..PROOF_ARTIFACT_V0_LEN), |index| {
            let model = LogisticModelV0 {
                weights: vec![0.1, -0.2, 0.3, 0.4],
                bias: -0.05,
            };
            let input = InputV0 {
                x: vec![1.0, 2.0, 3.0, 4.0],
            };

            let model_bin = model.encode_bin();
            let input_bin = input.encode_bin();

            let runtime_id = [7u8; 32];
            let signing_key = [9u8; 32];

            let (output_bin, artifact_bin) =
                prove_lr_v0(runtime_id, signing_key, &model_bin, &input_bin).unwrap();

            let mut mutated = artifact_bin.clone();
            mutated[index] ^= 0xFF;

            prop_assert!(verify_lr_v0(&mutated, &model_bin, &input_bin, &output_bin).is_err());
            Ok(())
        })
        .expect("verify must reject any mutated artifact");
}
