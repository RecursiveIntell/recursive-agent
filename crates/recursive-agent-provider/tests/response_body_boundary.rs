//! Real loopback HTTP tests of the non-streaming response decoding boundary.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use recursive_agent_provider::{
    CompletionBackend, CompletionRequestV1, CompletionResponseV1, ConversationMessageV1,
    ConversationMessageV2, ConversationRequestV1, ConversationRequestV2, ConversationRoleV1,
    CredentialRef, CredentialResolveError, CredentialResolver, HttpCompletionBackend,
    ProviderError, ProviderSpecV1, SecretBytes, ValidatedEndpoint,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const LIMIT: usize = 1 << 20;

#[test]
fn legacy_openai_completion_uses_same_boundary() -> TestResult {
    const CHILD: &str = "RA_RESPONSE_BOUNDARY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Fixture credentials exist only in this disposable child's environment.
        // Never mutate environment while other test threads are running.
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "legacy_openai_completion_uses_same_boundary",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("RA_RESPONSE_BOUNDARY_FIXTURE", "loopback-fixture-only")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    for framing in [Framing::Length, Framing::Chunked, Framing::Close] {
        assert_eq!(
            request(Route::LegacyOpenAi, valid_body(LIMIT), framing, 200)??.text,
            "ok"
        );
        assert!(
            matches!(request(Route::LegacyOpenAi, valid_body(LIMIT + 1), framing, 200)?,
            Err(ProviderError::ResponseBodyTooLarge { maximum_bytes }) if maximum_bytes == LIMIT)
        );
    }
    for body in [
        br#"{"choices":[{"message":{"content":"ok"}}],"x":1,"\u0078":2}"#.to_vec(),
        b"SENSITIVE_FIXTURE_NOT_A_KEY".to_vec(),
        b"\xff".to_vec(),
        b"{} {}".to_vec(),
    ] {
        let error = request(Route::LegacyOpenAi, body, Framing::Length, 200)?
            .err()
            .ok_or("invalid response accepted")?;
        assert_eq!(
            error.to_string(),
            "malformed provider response: provider response JSON is invalid"
        );
    }
    assert!(matches!(
        request(Route::LegacyOpenAi, b"{".to_vec(), Framing::Truncated, 200)?,
        Err(ProviderError::Http {
            operation: "response_read"
        })
    ));
    assert!(matches!(
        request(
            Route::LegacyOpenAi,
            vec![b'x'; LIMIT + 1],
            Framing::Length,
            429
        )?,
        Err(ProviderError::HttpStatus { status: 429 })
    ));
    Ok(())
}

#[derive(Clone, Copy)]
enum Route {
    Ollama,
    LegacyOpenAi,
    ConversationV1,
    ConversationV2,
}
const ROUTES: [Route; 3] = [Route::Ollama, Route::ConversationV1, Route::ConversationV2];
#[derive(Clone, Copy)]
enum Framing {
    Length,
    Chunked,
    Close,
    Truncated,
}

struct FixtureResolver;
impl CredentialResolver for FixtureResolver {
    fn resolve(&self, _: &CredentialRef) -> Result<SecretBytes, CredentialResolveError> {
        Ok(SecretBytes::new(b"loopback-fixture-only".to_vec()))
    }
}

fn request(
    route: Route,
    body: Vec<u8>,
    framing: Framing,
    status: u16,
) -> Result<Result<CompletionResponseV1, ProviderError>, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = ValidatedEndpoint::try_new(format!("http://{}/", listener.local_addr()?))?;
    listener.set_nonblocking(true)?;
    let server = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("request closed early".into());
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.len() > 65536 {
                return Err("fixture request too large".into());
            }
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end]).map_err(|e| e.to_string())?;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>())
                    })
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .ok_or("no request length")?;
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let framing_header = match framing {
            Framing::Length => format!("Content-Length: {}\r\n", body.len()),
            Framing::Truncated => format!("Content-Length: {}\r\n", body.len() + 100),
            Framing::Chunked => "Transfer-Encoding: chunked\r\n".into(),
            Framing::Close => String::new(),
        };
        let headers = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\n{framing_header}Connection: close\r\n\r\n");
        let result = (|| -> std::io::Result<()> {
            stream.write_all(headers.as_bytes())?;
            if matches!(framing, Framing::Chunked) {
                for chunk in body.chunks(4096) {
                    write!(stream, "{:x}\r\n", chunk.len())?;
                    stream.write_all(chunk)?;
                    stream.write_all(b"\r\n")?;
                }
                stream.write_all(b"0\r\n\r\n")
            } else {
                stream.write_all(&body)
            }
        })();
        match result {
            Ok(()) => Ok(()),
            // Early size/status rejection closes the connection intentionally.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    });
    let backend = HttpCompletionBackend::new(Duration::from_secs(5))?;
    let result = match route {
        Route::Ollama => backend.complete(&CompletionRequestV1 {
            provider: ProviderSpecV1::Ollama {
                base_url: endpoint,
                model: "fixture".into(),
            },
            prompt: "fixture".into(),
            max_tokens: Some(8),
        }),
        Route::LegacyOpenAi => backend.complete(&CompletionRequestV1 {
            provider: ProviderSpecV1::OpenAiCompatible {
                base_url: endpoint,
                model: "fixture".into(),
                credential_ref: CredentialRef::try_new("environment:RA_RESPONSE_BOUNDARY_FIXTURE")?,
            },
            prompt: "fixture".into(),
            max_tokens: Some(8),
        }),
        Route::ConversationV1 | Route::ConversationV2 => {
            let provider = ProviderSpecV1::OpenAiCompatible {
                base_url: endpoint,
                model: "fixture".into(),
                credential_ref: CredentialRef::try_new("environment:FIXTURE_ONLY")?,
            };
            if matches!(route, Route::ConversationV1) {
                backend.complete_conversation_with_resolver(
                    &ConversationRequestV1::try_new(
                        provider,
                        vec![ConversationMessageV1::new(
                            ConversationRoleV1::User,
                            "fixture",
                        )],
                        Some(8),
                    )?,
                    &FixtureResolver,
                )
            } else {
                backend.complete_conversation_v2_with_resolver(
                    &ConversationRequestV2::try_new(
                        provider,
                        vec![ConversationMessageV2::user("fixture")],
                        Some(8),
                    )?,
                    &FixtureResolver,
                )
            }
        }
    };
    server
        .join()
        .map_err(|_| "fixture server panicked")?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    Ok(result)
}

fn valid_body(size: usize) -> Vec<u8> {
    let prefix = r#"{"response":"ok","choices":[{"message":{"content":"ok"}}],"padding":""#;
    let suffix = "\"}";
    assert!(size >= prefix.len() + suffix.len());
    format!(
        "{prefix}{}{suffix}",
        "x".repeat(size - prefix.len() - suffix.len())
    )
    .into_bytes()
}

#[test]
fn rejects_recursive_decoded_duplicate_response_keys() -> TestResult {
    for route in ROUTES {
        for suffix in [
            r#""x":1,"x":2"#,
            r#""x":1,"\u0078":2"#,
            r#""nested":[{"x":1,"\u0078":2}]"#,
        ] {
            let body = format!(
                r#"{{"response":"ok","choices":[{{"message":{{"content":"ok"}}}}],{suffix}}}"#
            );
            assert!(matches!(
                request(route, body.into_bytes(), Framing::Length, 200)?,
                Err(ProviderError::Malformed(_))
            ));
        }
    }
    Ok(())
}

#[test]
fn rejects_oversized_success_for_known_chunked_and_close_lengths() -> TestResult {
    for route in ROUTES {
        for framing in [Framing::Length, Framing::Chunked, Framing::Close] {
            let result = request(route, valid_body(LIMIT + 1), framing, 200)?;
            let error = result.err().ok_or("oversized response accepted")?;
            assert!(
                matches!(error, ProviderError::ResponseBodyTooLarge { maximum_bytes } if maximum_bytes == LIMIT)
            );
        }
    }
    Ok(())
}

#[test]
fn accepts_exact_limit_and_distinct_sibling_keys_without_numeric_changes() -> TestResult {
    for route in ROUTES {
        for framing in [Framing::Length, Framing::Chunked, Framing::Close] {
            assert_eq!(request(route, valid_body(LIMIT), framing, 200)??.text, "ok");
        }
        let body = br#"{"response":"ok","choices":[{"message":{"content":"ok"}}],"siblings":[{"x":1},{"x":2}],"integer":18446744073709551615}"#;
        assert_eq!(
            request(route, body.to_vec(), Framing::Length, 200)??.raw["integer"].as_u64(),
            Some(u64::MAX)
        );
    }
    Ok(())
}

#[test]
fn rejects_malformed_utf8_trailing_and_truncated_bodies_without_echo() -> TestResult {
    for route in ROUTES {
        for body in [
            b"SENSITIVE_FIXTURE_NOT_A_KEY".to_vec(),
            b"\xff".to_vec(),
            b"{} {}".to_vec(),
        ] {
            let error = request(route, body, Framing::Length, 200)?
                .err()
                .ok_or("invalid body accepted")?;
            assert_eq!(
                error.to_string(),
                "malformed provider response: provider response JSON is invalid"
            );
        }
        assert!(matches!(
            request(route, b"{\"response\":".to_vec(), Framing::Truncated, 200)?,
            Err(ProviderError::Http {
                operation: "response_read"
            })
        ));
    }
    Ok(())
}

#[test]
fn non_success_status_remains_status_without_diagnostic_body_echo() -> TestResult {
    for route in ROUTES {
        for status in [401, 403, 429, 500, 503, 302] {
            let error = request(
                route,
                b"SENSITIVE_FIXTURE_NOT_A_KEY".to_vec(),
                Framing::Truncated,
                status,
            )?
            .err()
            .ok_or("status accepted")?;
            assert!(
                matches!(error, ProviderError::HttpStatus { status: observed } if observed == status)
            );
            assert!(!format!("{error:?}").contains("SENSITIVE_FIXTURE_NOT_A_KEY"));
        }
    }
    Ok(())
}
