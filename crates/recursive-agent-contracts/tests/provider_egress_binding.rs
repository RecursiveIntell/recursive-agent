use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    parse_provider_egress_binding_v1_bytes, ContentDigest, ProviderEgressBindingIngressError,
    ProviderEgressBindingMaterialV1, ProviderEgressBindingV1,
};

fn material() -> Result<ProviderEgressBindingMaterialV1, Box<dyn std::error::Error>> {
    Ok(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: "policy:fixture".into(),
        policy_basis_digest: format!("blake3:{}", "a".repeat(64)),
        context_digest: format!("sha256:{}", "b".repeat(64)),
        source_revision: "source:fixture".into(),
        graph_obligation_ref: "graph-obligation:node-1".into(),
        graph_obligation_digest: format!("blake3:{}", "c".repeat(64)),
        route_class: "local".into(),
        provider_identity: "ollama:http://127.0.0.1:11434".into(),
        model_ref: "model:fixture".into(),
        input_tokens: 12,
        output_reserve: 8,
        request_digest: ContentDigest::compute(b"exact-provider-request"),
        not_after: Utc
            .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
            .single()
            .ok_or("bad fixture time")?,
    })
}

#[test]
fn egress_binding_is_digest_bound_and_rejects_hostile_or_expired_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = ProviderEgressBindingV1::seal(material()?)?;
    binding.validate_at(
        Utc.with_ymd_and_hms(2026, 9, 5, 0, 0, 0)
            .single()
            .ok_or("bad fixture time")?,
    )?;
    assert_eq!(
        binding.request_digest,
        ContentDigest::compute(b"exact-provider-request")
    );
    assert_eq!(binding.graph_obligation_ref, "graph-obligation:node-1");
    assert_eq!(
        parse_provider_egress_binding_v1_bytes(&serde_json::to_vec(&binding)?)?,
        binding
    );

    let mut tampered = serde_json::to_value(&binding)?;
    tampered["route_class"] = serde_json::json!("cloud");
    assert!(matches!(
        parse_provider_egress_binding_v1_bytes(&serde_json::to_vec(&tampered)?),
        Err(ProviderEgressBindingIngressError::Semantic(_))
    ));
    let mut graph_tampered = serde_json::to_value(&binding)?;
    graph_tampered["graph_obligation_digest"] =
        serde_json::json!(format!("blake3:{}", "d".repeat(64)));
    assert!(matches!(
        parse_provider_egress_binding_v1_bytes(&serde_json::to_vec(&graph_tampered)?),
        Err(ProviderEgressBindingIngressError::Semantic(_))
    ));
    let mut unknown = serde_json::to_value(&binding)?;
    unknown["unknown"] = serde_json::json!(true);
    assert!(matches!(
        parse_provider_egress_binding_v1_bytes(&serde_json::to_vec(&unknown)?),
        Err(ProviderEgressBindingIngressError::Malformed)
    ));
    assert!(binding
        .validate_at(
            Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0)
                .single()
                .ok_or("bad fixture time")?
        )
        .is_err());
    Ok(())
}
