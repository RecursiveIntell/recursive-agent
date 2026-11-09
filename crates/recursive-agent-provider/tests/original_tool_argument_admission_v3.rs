//! Provider-boundary contract: tool-call parsing preserves decoded argument bytes.
//! This fixture does not exercise a selected daemon or production Libraries
//! dispatch route. A separate disposable joined dispatcher test exists; the
//! installed route remains a separate acceptance gate.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use recursive_agent_provider::{
    ConversationMessageV2, ConversationRequestV2, CredentialRef, CredentialResolveError,
    CredentialResolver, HttpCompletionBackend, ProviderError, ProviderSpecV1, SecretBytes,
    ValidatedEndpoint,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct FixtureResolver;
impl CredentialResolver for FixtureResolver {
    fn resolve(&self, _: &CredentialRef) -> Result<SecretBytes, CredentialResolveError> {
        Ok(SecretBytes::new(b"local-fixture-only".to_vec()))
    }
}

fn one_response(body: &'static str) -> TestResultWithServer {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/", listener.local_addr()?);
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request)?;
            if count == 0 || !request[..count].starts_with(b"POST /v1/chat/completions ") {
                return Err("unexpected fixture request".into());
            }
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            stream.write_all(reply.as_bytes())?;
            Ok(())
        })();
        let _ = tx.send(result.map_err(|error| error.to_string()));
    });
    Ok((url, rx, server))
}

type TestResultWithServer = Result<
    (
        String,
        mpsc::Receiver<Result<(), String>>,
        thread::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
>;

fn request(url: String) -> Result<ConversationRequestV2, ProviderError> {
    ConversationRequestV2::try_new(
        ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new(url)?,
            model: "fixture-model".into(),
            credential_ref: CredentialRef::try_new("environment:UNUSED_FIXTURE_KEY")?,
        },
        vec![ConversationMessageV2::user("inspect")],
        Some(64),
    )
}

#[test]
fn v3_tool_response_preserves_unmodified_argument_bytes_and_admitted_value() -> TestResult {
    let arguments = r#"{"distinct":1,"other":2}"#;
    let body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"distinct\":1,\"other\":2}"}}]}}]}"#;
    let (url, outcome, server) = one_response(body)?;
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let result = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver)?;
    assert_eq!(result.tool_calls.len(), 1);
    assert_eq!(result.tool_calls[0].name, "lookup");
    assert_eq!(
        result.tool_calls[0].original_arguments,
        arguments.as_bytes()
    );
    assert_eq!(
        result.tool_calls[0].admitted_arguments,
        json!({"distinct":1,"other":2})
    );
    outcome
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}

#[test]
fn v3_tool_response_denies_decoded_shadow_keys_before_any_downstream_dispatch() -> TestResult {
    // The outer HTTP body is valid JSON. Only the JSON *inside* function.arguments
    // duplicates a decoded key; reserializing a Value first would lose that fact.
    let body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1,\"\\u0078\":2}"}}]}}]}"#;
    let (url, outcome, server) = one_response(body)?;
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let mut dispatches = 0;
    let result = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    if let Ok(ref accepted) = result {
        dispatches += accepted.tool_calls.len();
    }
    assert!(matches!(
        result,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    assert_eq!(dispatches, 0);
    outcome
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}

#[test]
fn v3_tool_response_rejects_unknown_function_fields_without_releasing_proposals() -> TestResult {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}","unadmitted":"sidecar"}}]}}]}"#;
    let (url, outcome, server) = one_response(body)?;
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let result = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    assert!(matches!(
        result,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    outcome
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}

#[test]
fn v3_tool_response_rejects_unknown_message_field() -> TestResult {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":null,"unadmitted":1,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}}]}}]}"#;
    let (url, outcome, server) = one_response(body)?;
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let result = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    assert!(matches!(
        result,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    outcome
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}

#[test]
fn v3_tool_response_rejects_non_assistant_role() -> TestResult {
    let body = r#"{"choices":[{"message":{"role":"user","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}}]}}]}"#;
    let (url, outcome, server) = one_response(body)?;
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let result = backend.receive_tool_calls_v3_with_resolver(&request(url)?, &FixtureResolver);
    assert!(matches!(
        result,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    outcome
        .recv_timeout(Duration::from_secs(5))?
        .map_err(|e| format!("server: {e}"))?;
    server.join().map_err(|_| "server panic")?;
    Ok(())
}
