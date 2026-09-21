//! Native decoding is an error/UTF-8 adapter, not a second JSON owner.
use recursive_agent_contracts::{
    parse_child_operation_envelope_v2_bytes, parse_child_operation_proposal_v2_bytes,
    parse_operation_envelope_bytes, parse_strict_json_value, OperationIngressError,
    StrictJsonError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn native_contract_delegates_to_one_canonical_raw_owner() {
    let source = include_str!("../src/lib.rs");
    assert!(source.contains("boundary_compiler::parse_and_validate("));
    assert!(!source.contains("struct DuplicateSafeValue"));
    assert!(!include_str!("../src/operation.rs").contains("DuplicateSafeValue"));
}

#[test]
fn duplicate_free_values_match_the_owner() -> TestResult {
    for raw in [
        "null",
        "true",
        "-1",
        "18446744073709551615",
        "9007199254740993",
        "-0.0",
        "1e22",
        r#"[{"x":1},{"x":2}]"#,
        r#"{"a":{"x":1},"b":{"x":2},"unicode":{"é":1,"e\u0301":2}}"#,
    ] {
        assert_eq!(
            parse_strict_json_value(raw.as_bytes())?,
            boundary_compiler::parse_and_validate(raw)?
        );
    }
    Ok(())
}

#[test]
fn duplicate_errors_are_typed_and_recursive() {
    for raw in [
        r#"{"x":1,"x":2}"#,
        r#"{"x":1,"\u0078":2}"#,
        r#"{"a":[{"x":1,"\u0078":2}]}"#,
        r#"{"😀":1,"\ud83d\ude00":2}"#,
        r#"{"a\"b":1,"a\u0022b":2}"#,
    ] {
        assert!(matches!(
            boundary_compiler::parse_and_validate(raw),
            Err(boundary_compiler::JcsError::DuplicateKey { .. })
        ));
        assert_eq!(
            parse_strict_json_value(raw.as_bytes()),
            Err(StrictJsonError::DuplicateKey)
        );
    }
}

#[test]
fn malformed_and_invalid_utf8_remain_malformed() {
    for raw in [
        b"{} {}".as_slice(),
        b"\xff",
        b"{",
        b"NaN",
        b"1e9999",
        br#""\ud800""#,
        br#"{"\uZZZZ":1}"#,
    ] {
        assert_eq!(
            parse_strict_json_value(raw),
            Err(StrictJsonError::Malformed)
        );
    }
}

#[test]
fn every_operation_parser_retains_duplicate_and_malformed_categories() {
    let duplicate = br#"{"x":1,"\u0078":2}"#;
    assert!(matches!(
        parse_operation_envelope_bytes(duplicate),
        Err(OperationIngressError::DuplicateKey)
    ));
    assert!(matches!(
        parse_child_operation_proposal_v2_bytes(duplicate),
        Err(OperationIngressError::DuplicateKey)
    ));
    assert!(matches!(
        parse_child_operation_envelope_v2_bytes(duplicate),
        Err(OperationIngressError::DuplicateKey)
    ));
    for malformed in [b"\xff".as_slice(), b"{} {}", b"{"] {
        assert!(matches!(
            parse_operation_envelope_bytes(malformed),
            Err(OperationIngressError::Malformed)
        ));
        assert!(matches!(
            parse_child_operation_proposal_v2_bytes(malformed),
            Err(OperationIngressError::Malformed)
        ));
        assert!(matches!(
            parse_child_operation_envelope_v2_bytes(malformed),
            Err(OperationIngressError::Malformed)
        ));
    }
}
