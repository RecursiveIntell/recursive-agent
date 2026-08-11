//! Regression contract for the default tool policy surface.

use recursive_agent_policy::Allowlist;

#[test]
fn repo_audit_is_explicitly_policy_admitted() {
    let allowlist = Allowlist::default();
    assert!(
        allowlist.allowed.contains("repo_audit"),
        "the daemon may register repo_audit only when policy admits it"
    );
}
