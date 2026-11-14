//! Strict decoding for the existing public state enums. Empty struct wire
//! variants close serde's internally-tagged unit-variant unknown-field hole,
//! without changing public Rust constructors or their serialized V1 wire shape.
use super::*;

impl<'de> serde::Deserialize<'de> for PermitStateV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Issued {},
            Consumed {
                consumed_at: DateTime<Utc>,
            },
            Revoked {
                revoked_at: DateTime<Utc>,
                reason: PermitRevocationReasonV1,
            },
        }
        Ok(
            match <Wire as serde::Deserialize>::deserialize(deserializer)? {
                Wire::Issued {} => Self::Issued,
                Wire::Consumed { consumed_at } => Self::Consumed { consumed_at },
                Wire::Revoked { revoked_at, reason } => Self::Revoked { revoked_at, reason },
            },
        )
    }
}
impl<'de> serde::Deserialize<'de> for PermitEvidenceStateV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Issued {},
            Consumed {
                at: DateTime<Utc>,
            },
            Rejected {
                at: DateTime<Utc>,
                reason: PermitRejectionReasonV1,
            },
            Revoked {
                at: DateTime<Utc>,
                reason: PermitRevocationReasonV1,
            },
        }
        Ok(
            match <Wire as serde::Deserialize>::deserialize(deserializer)? {
                Wire::Issued {} => Self::Issued,
                Wire::Consumed { at } => Self::Consumed { at },
                Wire::Rejected { at, reason } => Self::Rejected { at, reason },
                Wire::Revoked { at, reason } => Self::Revoked { at, reason },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_v1_issued_wire_shape_is_unchanged_and_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let valid = br#"{"state":"issued"}"#.as_slice();
        let state: PermitStateV1 = serde_json::from_slice(valid)?;
        let evidence: PermitEvidenceStateV1 = serde_json::from_slice(valid)?;
        assert_eq!(serde_json::to_vec(&state)?, valid);
        assert_eq!(serde_json::to_vec(&evidence)?, valid);
        let invalid = br#"{"state":"issued","unexpected":"must-reject"}"#;
        assert!(serde_json::from_slice::<PermitStateV1>(invalid).is_err());
        assert!(serde_json::from_slice::<PermitEvidenceStateV1>(invalid).is_err());
        Ok(())
    }
}
