use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use recursive_agent_provider::{
    CompletionBackend, CompletionRequestV1, ConversationMessageV2, ConversationRequestV2,
    CredentialRef, CredentialResolveError, CredentialResolver, HttpCompletionBackend,
    ProviderError, ProviderSpecV1, SecretBytes, ToolCallV2, ValidatedEndpoint,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RequestReceiver = Receiver<Vec<u8>>;

struct FixedResolver;

impl CredentialResolver for FixedResolver {
    fn resolve(
        &self,
        _credential_ref: &CredentialRef,
    ) -> Result<SecretBytes, CredentialResolveError> {
        Ok(SecretBytes::new(b"fixture-token".to_vec()))
    }
}

fn receive_exact_request(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("connection closed before request headers".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()?
        .ok_or("missing content length")?;
    while bytes.len() < header_end + content_length {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("connection closed before complete request body".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn response_server(
    status: &str,
    body: &str,
) -> Result<(String, RequestReceiver), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let status = status.to_owned();
    let body = body.to_owned();
    thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let request = receive_exact_request(&mut stream).map_err(|error| error.to_string())?;
            let location = if status.starts_with("302 ") {
                "Location: /redirected\r\n"
            } else {
                ""
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes())?;
            sender.send(request)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = sender.send(format!("SERVER_ERROR:{error}").into_bytes());
        }
    });
    Ok((format!("http://{address}/"), receiver))
}

#[test]
fn v2_transport_sends_prepared_body_once_and_returns_provider_content() -> TestResult {
    let (base_url, received) = response_server(
        "200 OK",
        r#"{"choices":[{"message":{"content":"fixture response"}}]}"#,
    )?;
    let request = ConversationRequestV2::try_new(
        ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new(base_url)?,
            model: "fixture-model".into(),
            credential_ref: CredentialRef::try_new("environment:UNUSED")?,
        },
        vec![
            ConversationMessageV2::user("inspect the state"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-1",
                "lookup",
                json!({"query": "status"}),
            )?])?,
            ConversationMessageV2::tool_result("call-1", "clean")?,
        ],
        Some(64),
    )?;

    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let response = backend.complete_conversation_v2_with_resolver(&request, &FixedResolver)?;

    assert_eq!(response.model, "fixture-model");
    assert_eq!(response.text, "fixture response");
    let request_bytes = received.recv_timeout(Duration::from_secs(5))?;
    let request_text = String::from_utf8(request_bytes)?;
    assert!(request_text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(request_text.contains("authorization: Bearer fixture-token\r\n"));
    let body = request_text
        .split_once("\r\n\r\n")
        .ok_or("missing HTTP body")?
        .1;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body)?,
        json!({
            "model": "fixture-model",
            "messages": [
                {"role": "user", "content": "inspect the state"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"query\":\"status\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call-1", "content": "clean"}
            ],
            "max_tokens": 64,
            "stream": false
        })
    );
    Ok(())
}

#[test]
fn legacy_completion_does_not_follow_loopback_redirects() -> TestResult {
    let (base_url, received) = response_server("302 Found", "")?;
    let request = CompletionRequestV1 {
        provider: ProviderSpecV1::Ollama {
            base_url: ValidatedEndpoint::try_new(base_url)?,
            model: "fixture-model".into(),
        },
        prompt: "redirect fixture".into(),
        max_tokens: None,
    };

    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let error = backend
        .complete(&request)
        .err()
        .ok_or("redirect response unexpectedly succeeded")?;
    assert!(matches!(error, ProviderError::HttpStatus { status: 302 }));
    let request_bytes = received.recv_timeout(Duration::from_secs(5))?;
    let request_text = String::from_utf8(request_bytes)?;
    assert!(request_text.starts_with("POST /api/generate HTTP/1.1\r\n"));
    Ok(())
}
