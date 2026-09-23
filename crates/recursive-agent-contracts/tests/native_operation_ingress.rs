use recursive_agent_contracts::{
    parse_native_operation_bytes, NativeOperationIngressError, MAX_RUN_SPEC_INPUT_BYTES,
};

#[test]
fn native_family_admission_rejects_hostile_original_bytes_before_typed_conversion() {
    for input in [
        br#"{"schema":"recursive-agent.operation/v3","\u0073chema":"recursive-agent.operation/v1"}"#.as_slice(),
        br#"{"schema":"recursive-agent.operation/v3","nested":[{"x":1,"\u0078":2}]}"#,
    ] {
        assert!(matches!(
            parse_native_operation_bytes(input),
            Err(NativeOperationIngressError::DuplicateKey)
        ));
    }
    for input in [b"\xff".as_slice(), b"{} {}", b"{"] {
        assert!(matches!(
            parse_native_operation_bytes(input),
            Err(NativeOperationIngressError::Malformed)
        ));
    }
    assert!(matches!(
        parse_native_operation_bytes(br#"{"schema":"recursive-agent.operation/v9"}"#),
        Err(NativeOperationIngressError::UnsupportedSchema)
    ));
    assert!(matches!(
        parse_native_operation_bytes(&vec![b'x'; MAX_RUN_SPEC_INPUT_BYTES as usize + 1]),
        Err(NativeOperationIngressError::InputTooLarge { .. })
    ));
}
