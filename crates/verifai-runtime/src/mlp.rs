use verifai_core::event_bin::{ActivationKind, TraceEventV0};
use verifai_core::model_bin::{InputV0, MlpModelV1, OutputV0};
use verifai_core::bytes::BytesError;

use crate::VerifaiError;

pub struct MlpRun {
    pub output: OutputV0,
    pub events: Vec<TraceEventV0>,
}

pub fn run_mlp_v1(model_bin: &[u8], input_bin: &[u8]) -> Result<MlpRun, VerifaiError> {
    let model = MlpModelV1::decode_bin(model_bin).map_err(map_core)?;
    let input = InputV0::decode_bin(input_bin).map_err(map_core)?;
    if input.x.len() != model.input_dim as usize {
        return Err(VerifaiError::DimensionMismatch);
    }

    let hidden_size = model.hidden_size as usize;
    let mut hidden = vec![0.0_f64; hidden_size];
    for h in 0..hidden_size {
        let mut z = model.b1[h];
        let row_offset = h * model.input_dim as usize;
        for (i, &x) in input.x.iter().enumerate() {
            z += model.w1[row_offset + i] * x;
        }
        hidden[h] = z;
    }

    let mut events = Vec::with_capacity(hidden_size * 2 + 3);

    for h in 0..hidden_size {
        events.push(TraceEventV0::OpLinear {
            op_id: h as u32,
            z: hidden[h],
        });
        let activated = if hidden[h] > 0.0 { hidden[h] } else { 0.0 };
        events.push(TraceEventV0::OpActivation {
            op_id: 100 + h as u32,
            kind: ActivationKind::Relu,
            input: hidden[h],
            output: activated,
        });
        hidden[h] = activated;
    }

    let mut z2 = model.b2;
    for h in 0..hidden_size {
        z2 += model.w2[h] * hidden[h];
    }

    events.push(TraceEventV0::OpLinear {
        op_id: 200,
        z: z2,
    });
    let y = 1.0_f64 / (1.0_f64 + (-z2).exp());
    events.push(TraceEventV0::OpActivation {
        op_id: 300,
        kind: ActivationKind::Sigmoid,
        input: z2,
        output: y,
    });
    events.push(TraceEventV0::OpOutput { y });

    Ok(MlpRun {
        output: OutputV0 { y },
        events,
    })
}

fn map_core(_e: BytesError) -> VerifaiError {
    VerifaiError::CoreDecode
}
