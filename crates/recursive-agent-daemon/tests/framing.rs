use recursive_agent_daemon::{decode_frame_payload, FrameDecodeError, MAX_FRAME_PAYLOAD_BYTES};

#[test]
fn partial_prefix_requires_more_without_payload_allocation() {
    for received in 0..4 {
        let input = vec![0_u8; received];
        assert_eq!(
            decode_frame_payload(&input),
            Err(FrameDecodeError::IncompletePrefix { received })
        );
    }
}

#[test]
fn oversized_declared_length_is_rejected_from_prefix_alone(
) -> Result<(), Box<dyn std::error::Error>> {
    let declared = MAX_FRAME_PAYLOAD_BYTES + 1;
    let prefix = u32::try_from(declared)?.to_be_bytes();
    assert_eq!(
        decode_frame_payload(&prefix),
        Err(FrameDecodeError::DeclaredLengthTooLarge {
            declared,
            max: MAX_FRAME_PAYLOAD_BYTES,
        })
    );
    Ok(())
}

#[test]
fn truncated_payload_reports_declared_and_received_lengths() {
    let mut frame = 5_u32.to_be_bytes().to_vec();
    frame.extend_from_slice(b"abc");
    assert_eq!(
        decode_frame_payload(&frame),
        Err(FrameDecodeError::TruncatedPayload {
            declared: 5,
            received: 3,
        })
    );
}

#[test]
fn exact_frame_returns_only_the_borrowed_payload() -> Result<(), Box<dyn std::error::Error>> {
    let payload = b"abc";
    let mut frame = u32::try_from(payload.len())?.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    assert_eq!(decode_frame_payload(&frame), Ok(payload.as_slice()));
    Ok(())
}

#[test]
fn trailing_bytes_after_exact_frame_are_rejected() {
    let mut frame = 3_u32.to_be_bytes().to_vec();
    frame.extend_from_slice(b"abcx");
    assert_eq!(
        decode_frame_payload(&frame),
        Err(FrameDecodeError::TrailingBytes {
            declared: 3,
            trailing: 1,
        })
    );
}
