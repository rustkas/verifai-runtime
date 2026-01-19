use verifai_core::bytes::BytesError;
use verifai_core::event_bin::{ActivationKind, TraceEventV0};
use verifai_core::model_bin::{InputV0, LogisticModelV0, OutputV0};

use crate::VerifaiError;

pub struct LrRun {
    pub output: OutputV0,
    pub events: Vec<TraceEventV0>,
}

pub fn run_lr_v0(model_bin: &[u8], input_bin: &[u8]) -> Result<LrRun, VerifaiError> {
    let model = LogisticModelV0::decode_bin(model_bin).map_err(map_core)?;
    let input = InputV0::decode_bin(input_bin).map_err(map_core)?;
    if model.weights.len() != input.x.len() {
        return Err(VerifaiError::DimensionMismatch);
    }

    let mut z = model.bias;
    for (w, x) in model.weights.iter().zip(input.x.iter()) {
        z += w * x;
    }

    let y = 1.0_f64 / (1.0_f64 + (-z).exp());

    let events = vec![
        TraceEventV0::OpLinear { op_id: 0, z },
        TraceEventV0::OpActivation {
            op_id: 1,
            kind: ActivationKind::Sigmoid,
            input: z,
            output: y,
        },
        TraceEventV0::OpOutput { y },
    ];

    Ok(LrRun {
        output: OutputV0 { y },
        events,
    })
}

fn map_core(_e: BytesError) -> VerifaiError {
    VerifaiError::CoreDecode
}
