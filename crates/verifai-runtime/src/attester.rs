use verifai_core::attestation::AttestationBundle;

/// Trait to provide platform-specific attestation for inference runs.
pub trait Attester {
    fn attest(measurement: [u8; 32]) -> AttestationBundle;
}

/// No-op attester used for MVP / testing.
pub struct NoopAttester;

impl Attester for NoopAttester {
    fn attest(measurement: [u8; 32]) -> AttestationBundle {
        AttestationBundle {
            attester_id: [0u8; 32],
            measurement,
            attestation: measurement.to_vec(),
        }
    }
}
