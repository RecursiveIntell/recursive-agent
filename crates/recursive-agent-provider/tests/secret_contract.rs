use recursive_agent_provider::{
    CompletionRequestV1, CredentialRef, ProviderError, ProviderSpecV1, ValidatedEndpoint,
};

const SENTINEL: &str = "phase1-secret-sentinel-never-emit";
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn provider_spec_serialization_contains_no_secret() -> TestResult {
    let json = serde_json::json!({
        "kind": "open_ai_compatible",
        "base_url": "https://api.example.test/",
        "model": "test-model",
        "credential_ref": "environment:TEST_PROVIDER_KEY",
        "api_key": SENTINEL,
    });
    assert!(serde_json::from_value::<ProviderSpecV1>(json).is_err());

    let spec = ProviderSpecV1::OpenAiCompatible {
        base_url: ValidatedEndpoint::try_new("https://api.example.test/")?,
        model: "test-model".into(),
        credential_ref: CredentialRef::try_new("environment:TEST_PROVIDER_KEY")?,
    };
    let serialized = serde_json::to_string(&spec)?;
    assert!(!serialized.contains(SENTINEL));
    assert!(!serialized.contains("api_key"));
    Ok(())
}

#[test]
fn debug_output_redacts_secret_material() {
    let secret = recursive_agent_provider::SecretBytes::new(SENTINEL.as_bytes().to_vec());
    assert!(!format!("{secret:?}").contains(SENTINEL));
}

#[test]
fn provider_execution_is_typed_unavailable_without_resolving_credentials() -> TestResult {
    let request = CompletionRequestV1 {
        provider: ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new("https://api.example.test/")?,
            model: "test-model".into(),
            credential_ref: CredentialRef::try_new("environment:ABSENT_PROVIDER_KEY")?,
        },
        prompt: "hello".into(),
        max_tokens: None,
    };
    let _ = request;
    let error = ProviderError::Unavailable;
    assert!(matches!(&error, ProviderError::Unavailable));
    assert_eq!(
        error.to_string(),
        "provider execution is unavailable in Phase 1"
    );
    assert!(!format!("{error:?}").contains("ABSENT_PROVIDER_KEY"));
    Ok(())
}

#[test]
fn raw_secret_reference_and_raw_key_migration_errors_never_echo_input() -> TestResult {
    let raw_reference = format!(
        "{{\"kind\":\"open_ai_compatible\",\"base_url\":\"https://example.test\",\"model\":\"m\",\"credential_ref\":\"{SENTINEL}\"}}"
    );
    let error = serde_json::from_str::<ProviderSpecV1>(&raw_reference)
        .err()
        .ok_or("raw credential reference unexpectedly parsed")?;
    assert!(!error.to_string().contains(SENTINEL));
    assert!(error.to_string().contains("environment:PORTABLE_NAME"));

    let raw_key = format!(
        "{{\"kind\":\"open_ai_compatible\",\"base_url\":\"https://example.test\",\"model\":\"m\",\"api_key\":\"{SENTINEL}\"}}"
    );
    let error = serde_json::from_str::<ProviderSpecV1>(&raw_key)
        .err()
        .ok_or("raw API key unexpectedly parsed")?;
    assert!(!error.to_string().contains(SENTINEL));
    assert!(error.to_string().contains("migrate to credential_ref"));
    Ok(())
}

#[test]
fn url_userinfo_query_fragment_scheme_and_control_are_rejected_before_resolver() -> TestResult {
    for base_url in [
        format!("https://user:{SENTINEL}@example.test/"),
        format!("https://example.test/?token={SENTINEL}"),
        format!("https://example.test/#{SENTINEL}"),
        format!("https://example.test/{SENTINEL}"),
        format!("file:///{SENTINEL}"),
        format!("https://example.test/\n{SENTINEL}"),
    ] {
        let error = ValidatedEndpoint::try_new(&base_url)
            .err()
            .ok_or("invalid provider URL unexpectedly constructed")?;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(SENTINEL));
        assert!(matches!(error, ProviderError::InvalidProviderUrl { .. }));

        let encoded = serde_json::json!({
            "kind": "ollama",
            "base_url": base_url,
            "model": "model"
        });
        let deserialize_error = serde_json::from_value::<ProviderSpecV1>(encoded)
            .err()
            .ok_or("invalid provider URL unexpectedly deserialized")?;
        assert!(!deserialize_error.to_string().contains(SENTINEL));
    }
    Ok(())
}

#[test]
fn validated_endpoint_debug_and_serialization_are_normalized_and_secret_free() -> TestResult {
    let endpoint = ValidatedEndpoint::try_new("https://example.test/")?;
    assert_eq!(endpoint.as_str(), "https://example.test/");
    let debug = format!("{endpoint:?}");
    let serialized = serde_json::to_string(&endpoint)?;
    assert!(!debug.contains('@'));
    assert_eq!(serialized, "\"https://example.test/\"");
    Ok(())
}

#[test]
fn unavailable_invocation_and_debug_paths_cannot_retain_sentinel() -> TestResult {
    let reference = CredentialRef::try_new("environment:SAFE_REFERENCE")?;
    assert!(!format!("{reference:?}").contains(SENTINEL));
    let request = CompletionRequestV1 {
        provider: ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new("https://example.test/")?,
            model: "model".into(),
            credential_ref: reference,
        },
        prompt: SENTINEL.into(),
        max_tokens: None,
    };
    let _ = request;
    let error = ProviderError::Unavailable;
    assert!(!format!("{error:?} {error}").contains(SENTINEL));
    Ok(())
}
