//! Funding-policy enrollment is not execution, a bank, or mission-owner admission.
use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::ContentDigest;
use recursive_agent_policy::{
    CampaignFundingExpectationV1, CampaignFundingGrantV1, DurablePermitStore,
    InferenceBudgetLimitsV1, InferenceBudgetTermsV1, NormalChatEgressGrantStore,
    NormalChatEgressGrantV1, NormalChatGrantAuthorityV1,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MISSION: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}
struct Fixture {
    root: tempfile::TempDir,
    path: PathBuf,
    normal: PathBuf,
    expected: CampaignFundingExpectationV1,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            path: root.path().join("funding.json"),
            normal: root.path().join("egress.json"),
            root,
            expected: CampaignFundingExpectationV1 {
                mission_contract_ref: format!("contract:{}", &MISSION[7..]),
                kanban_root_task_ref: "task:fixture".into(),
                ares_home_digest: HOME.into(),
                provider_identity: "openai-codex".into(),
                model_ref: "gpt-6-luna".into(),
                api_mode: "responses".into(),
                reasoning_effort: "xhigh".into(),
                budget_terms_digest: ContentDigest::compute(b"fixture terms, not a real tariff"),
                max_total_nanodollars: 5_000_000_000,
            },
        })
    }
    fn store(&self) -> Result<NormalChatEgressGrantStore, Box<dyn std::error::Error>> {
        Ok(NormalChatEgressGrantStore::from_dir_fd(&File::open(
            self.root.path(),
        )?)?)
    }
    fn authority(
        &self,
        revision: u64,
    ) -> Result<NormalChatGrantAuthorityV1, Box<dyn std::error::Error>> {
        let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
            "schema":"recursive-agent.normal-chat-egress-grant/v1","revision":revision,
            "ares_home_digest":HOME,"mode":"enforce","any_route":false,
            "routes":[{"provider_identity":"openai-codex","model_ref":"gpt-6-luna","api_mode":"responses"}],
            "caps":{"max_attempts":4,"max_output_tokens":100,"max_wall_time_ms":1000,"max_request_bytes":4096},
            "expires_at":now()+TimeDelta::hours(2),"content_retention":"digest_only","policy_digest":HOME
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        fs::write(&self.normal, serde_json::to_vec(&grant)?)?;
        fs::set_permissions(&self.normal, fs::Permissions::from_mode(0o600))?;
        Ok(self.store()?.load_from_path(&self.normal, HOME, now())?)
    }
    fn grant(
        &self,
        authority: &NormalChatGrantAuthorityV1,
    ) -> Result<CampaignFundingGrantV1, Box<dyn std::error::Error>> {
        let mut grant: CampaignFundingGrantV1 = serde_json::from_value(json!({
            "schema":"recursive-agent.campaign-funding-grant/v1",
            "mission_contract_ref":self.expected.mission_contract_ref,"mission_contract_digest":MISSION,
            "kanban_root_task_ref":self.expected.kanban_root_task_ref,"ares_home_digest":HOME,
            "egress_policy_digest":authority.grant().policy_digest,
            "provider_identity":"openai-codex","model_ref":"gpt-6-luna","api_mode":"responses","reasoning_effort":"xhigh",
            "budget_terms_digest":self.expected.budget_terms_digest,"max_total_nanodollars":5_000_000_000_u64,
            "not_before":now(),"expires_at":now()+TimeDelta::hours(1),"policy_digest":HOME
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        Ok(grant)
    }
    fn write(&self, grant: &CampaignFundingGrantV1) -> TestResult {
        fs::write(&self.path, serde_json::to_vec(grant)?)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    fn enroll(&self, authority: &NormalChatGrantAuthorityV1) -> TestResult {
        self.write(&self.grant(authority)?)?;
        self.store()?.initialize_campaign_funding_from_path(
            &self.path,
            authority,
            &self.expected,
            now,
        )?;
        Ok(())
    }
}
#[test]
fn funding_lifetime_is_separate_and_does_not_extend_execution_lease() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let control_root = tempfile::tempdir()?;
    let permits = DurablePermitStore::from_run_root_fd(&File::open(control_root.path())?)?;
    let control =
        permits.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    assert_eq!(
        control.permit().binding.expires_at,
        now() + TimeDelta::milliseconds(300_000)
    );
    assert!(!control.permit().binding.effect.network_allowed);
    let later = || now() + TimeDelta::minutes(6);
    assert!(permits
        .open_normal_chat_session_control(&authority, "conversation:fixture", None, later)
        .is_err());
    let loaded =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, later)?;
    assert_eq!(loaded.grant().expires_at, now() + TimeDelta::hours(1));
    fx.store()?
        .check_campaign_funding_current(&loaded, &authority, later)?;
    Ok(())
}
#[test]
fn startup_load_requires_explicit_existing_enrollment() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.write(&fx.grant(&authority)?)?;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(!fx
        .root
        .path()
        .join("campaign-funding.enrollment.v1.json")
        .exists());
    fx.enroll(&authority)?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_ok());
    Ok(())
}
#[test]
fn owned_regular_0600_and_strict_closed_json_are_required() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let grant = fx.grant(&authority)?;
    fx.write(&grant)?;
    fs::set_permissions(&fx.path, fs::Permissions::from_mode(0o644))?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    fx.write(&grant)?;
    let link = fx.root.path().join("link");
    symlink(&fx.path, &link)?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&link, &authority, &fx.expected, now)
        .is_err());
    let mut unknown = serde_json::to_value(&grant)?;
    unknown["network_allowed"] = json!(true);
    fs::write(&fx.path, serde_json::to_vec(&unknown)?)?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    fx.write(&grant)?;
    let bytes = fs::read_to_string(&fx.path)?;
    fs::write(
        &fx.path,
        bytes.replacen('{', "{\"schema\":\"duplicate\",", 1),
    )?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-funding.enrolled.v1")
        .exists());
    Ok(())
}
#[test]
fn exact_mission_task_home_route_effort_terms_and_ceiling_are_bound() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.write(&fx.grant(&authority)?)?;
    let mut variants = Vec::new();
    let mut e = fx.expected.clone();
    e.mission_contract_ref = "contract:wrong".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.kanban_root_task_ref = "task:other".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.ares_home_digest = MISSION.into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.provider_identity = "other".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.model_ref = "other".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.api_mode = "other".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.reasoning_effort = "low".into();
    variants.push(e);
    let mut e = fx.expected.clone();
    e.budget_terms_digest = ContentDigest::compute(b"other");
    variants.push(e);
    let mut e = fx.expected.clone();
    e.max_total_nanodollars += 1;
    variants.push(e);
    for expected in variants {
        assert!(fx
            .store()?
            .initialize_campaign_funding_from_path(&fx.path, &authority, &expected, now)
            .is_err());
    }
    assert!(!fx
        .root
        .path()
        .join(".campaign-funding.enrolled.v1")
        .exists());
    fx.enroll(&authority)?;
    Ok(())
}
#[test]
fn changing_funding_policy_cannot_renew_or_replenish_enrollment() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let before = fx.store()?.read_campaign_funding_enrollment()?;
    let mut changed = fx.grant(&authority)?;
    changed.expires_at += TimeDelta::minutes(1);
    changed.policy_digest = changed.computed_policy_digest()?;
    fx.write(&changed)?;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert_eq!(before, fx.store()?.read_campaign_funding_enrollment()?);
    Ok(())
}
#[test]
fn current_egress_head_is_required_not_just_a_loaded_old_grant() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let cap =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let newer = fx.authority(2)?;
    assert!(fx
        .store()?
        .check_campaign_funding_current(&cap, &authority, now)
        .is_err());
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &newer, &fx.expected, now)
        .is_err());
    assert!(fx.store()?.read_campaign_funding_enrollment().is_ok());
    Ok(())
}
#[test]
fn missing_or_corrupt_enrollment_is_not_reinitialized() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let path = fx.root.path().join("campaign-funding.enrollment.v1.json");
    let original = fs::read(&path)?;
    fs::remove_file(&path)?;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    fs::write(&path, original)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::write(&path, b"{}")?;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    Ok(())
}
#[test]
fn foreign_store_and_copied_enrollment_cannot_substitute_identity() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let cap =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let other = Fixture::new()?;
    let other_authority = other.authority(1)?;
    assert!(other
        .store()?
        .check_campaign_funding_current(&cap, &other_authority, now)
        .is_err());
    for name in [
        ".campaign-funding.enrolled.v1",
        "campaign-funding.enrollment.v1.json",
    ] {
        fs::copy(fx.root.path().join(name), other.root.path().join(name))?;
    }
    other.write(&fx.grant(&authority)?)?;
    assert!(other
        .store()?
        .load_campaign_funding_from_path(&other.path, &other_authority, &other.expected, now)
        .is_err());
    Ok(())
}
#[test]
fn clock_samples_inside_each_locked_operation_cannot_regress() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.write(&fx.grant(&authority)?)?;
    let mut calls = 0;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || {
            calls += 1;
            if calls == 1 {
                now() + TimeDelta::seconds(1)
            } else {
                now()
            }
        })
        .is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-funding.enrolled.v1")
        .exists());
    fx.enroll(&authority)?;
    let mut calls = 0;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || {
            calls += 1;
            if calls == 1 {
                now() + TimeDelta::seconds(1)
            } else {
                now()
            }
        })
        .is_err());
    let cap =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut calls = 0;
    assert!(fx
        .store()?
        .check_campaign_funding_current(&cap, &authority, || {
            calls += 1;
            if calls == 1 {
                now() + TimeDelta::seconds(1)
            } else {
                now()
            }
        })
        .is_err());
    Ok(())
}

#[test]
fn postpublication_expiry_preserves_fence_instead_of_reenrolling() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.write(&fx.grant(&authority)?)?;
    let mut calls = 0;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || {
            calls += 1;
            if calls < 3 {
                now()
            } else {
                now() + TimeDelta::hours(1)
            }
        })
        .is_err());
    assert!(fx.store()?.read_campaign_funding_enrollment().is_ok());
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || now()
            + TimeDelta::hours(1))
        .is_err());
    Ok(())
}

#[test]
fn independent_enrollers_have_exactly_one_immutable_winner() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.write(&fx.grant(&authority)?)?;
    let enroll = || match fx.store() {
        Ok(store) => store
            .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
            .is_ok(),
        Err(_) => false,
    };
    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(enroll);
        let second = scope.spawn(enroll);
        let first = first.join().map_err(|_| "first enroller panicked")?;
        let second = second.join().map_err(|_| "second enroller panicked")?;
        assert_ne!(first, second);
        Ok(())
    })?;
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_ok());
    Ok(())
}

#[test]
fn observe_grants_cannot_bootstrap_funding_authority() -> TestResult {
    let fx = Fixture::new()?;
    let original = fx.authority(1)?;
    let mut observe = original.grant().clone();
    observe.mode = recursive_agent_policy::NormalChatEgressModeV1::Observe;
    observe.revision = 2;
    observe.policy_digest = observe.computed_policy_digest()?;
    fs::write(&fx.normal, serde_json::to_vec(&observe)?)?;
    let authority = fx.store()?.load_from_path(&fx.normal, HOME, now())?;
    fx.write(&fx.grant(&authority)?)?;
    assert!(fx
        .store()?
        .initialize_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
        .is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-funding.enrolled.v1")
        .exists());
    Ok(())
}

#[test]
fn expiry_and_regressed_clocks_refuse_but_history_remains_readable() -> TestResult {
    let fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    fx.enroll(&authority)?;
    let cap =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || {
                now() + TimeDelta::seconds(1)
            })?;
    assert!(fx
        .store()?
        .check_campaign_funding_current(&cap, &authority, now)
        .is_err());
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || now()
            + TimeDelta::hours(1))
        .is_err());
    assert!(fx
        .store()?
        .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, || now()
            - TimeDelta::seconds(1))
        .is_err());
    assert!(fx.store()?.read_campaign_funding_enrollment().is_ok());
    Ok(())
}

fn terms() -> InferenceBudgetTermsV1 {
    InferenceBudgetTermsV1 {
        schema: "recursive-agent.inference-budget-terms/v1".into(),
        provider: "openai-codex".into(),
        model: "gpt-6-luna".into(),
        api_mode: "responses".into(),
        reasoning_effort: "xhigh".into(),
        tariff_digest: ContentDigest::compute(
            b"synthetic terms test, not a verified external tariff",
        ),
        limits: InferenceBudgetLimitsV1 {
            input_nanodollars_per_token: 100,
            output_nanodollars_per_token: 500,
            max_input_tokens_per_send: 100,
            max_output_tokens_per_send: 20,
            max_total_input_tokens: 10_000,
            max_total_output_tokens: 2_000,
            max_sends: 10,
            max_total_nanodollars: 5_000_000_000,
        },
    }
}
fn enroll_terms(
    fx: &mut Fixture,
    authority: &NormalChatGrantAuthorityV1,
    terms: &InferenceBudgetTermsV1,
) -> TestResult {
    // Bind even deliberately invalid terms structurally. Admission must check
    // their meaning, not assume a matching digest makes zero rates valid.
    fx.expected.budget_terms_digest = recursive_agent_contracts::content_digest(terms)?;
    fx.enroll(authority)
}

#[test]
fn terms_positive_binds_exact_artifact_without_writing_money_state() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    assert_eq!(
        terms.computed_digest()?,
        recursive_agent_contracts::content_digest(&terms)?
    );
    assert_eq!(terms.limits.quote_nanodollars()?, 20_000);
    enroll_terms(&mut fx, &authority, &terms)?;
    let store = fx.store()?;
    let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let before = fs::read(fx.root.path().join("campaign-funding.enrollment.v1.json"))?;
    let mut names_before = fs::read_dir(fx.root.path())?
        .map(|p| p.map(|p| p.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names_before.sort();
    store.check_campaign_inference_terms(&cap, &authority, &terms, now)?;
    assert_eq!(
        before,
        fs::read(fx.root.path().join("campaign-funding.enrollment.v1.json"))?
    );
    let mut names_after = fs::read_dir(fx.root.path())?
        .map(|p| p.map(|p| p.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names_after.sort();
    assert_eq!(names_before, names_after);
    assert!(!fx.root.path().join("inference-budget.v1.json").exists());
    Ok(())
}

#[test]
fn terms_digest_guard_refuses_semantically_valid_substitution() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let original = terms();
    enroll_terms(&mut fx, &authority, &original)?;
    let store = fx.store()?;
    let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut changed = original.clone();
    changed.tariff_digest = ContentDigest::compute(b"substituted otherwise-valid tariff");
    changed.validate()?;
    assert!(
        store
            .check_campaign_inference_terms(&cap, &authority, &changed, now)
            .is_err(),
        "exact terms digest substitution was admitted"
    );
    store.check_campaign_inference_terms(&cap, &authority, &original, now)?;
    Ok(())
}

#[test]
fn terms_every_rate_and_resource_field_changes_the_enrolled_identity() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let original = terms();
    enroll_terms(&mut fx, &authority, &original)?;
    let store = fx.store()?;
    let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let raw = serde_json::to_value(&original)?;
    for field in [
        "input_nanodollars_per_token",
        "output_nanodollars_per_token",
        "max_input_tokens_per_send",
        "max_output_tokens_per_send",
        "max_total_input_tokens",
        "max_total_output_tokens",
        "max_sends",
        "max_total_nanodollars",
    ] {
        let mut changed = raw.clone();
        let current = changed["limits"][field].as_u64().ok_or("missing limit")?;
        changed["limits"][field] = json!(current + 1);
        let changed: InferenceBudgetTermsV1 = serde_json::from_value(changed)?;
        changed.validate()?;
        assert_ne!(changed.computed_digest()?, original.computed_digest()?);
        assert!(
            store
                .check_campaign_inference_terms(&cap, &authority, &changed, now)
                .is_err(),
            "substitution {field}"
        );
    }
    Ok(())
}

#[test]
fn terms_matching_digest_cannot_bypass_route_or_ceiling_binding() -> TestResult {
    for field in [
        "provider",
        "model",
        "api_mode",
        "reasoning_effort",
        "ceiling",
    ] {
        let mut fx = Fixture::new()?;
        let authority = fx.authority(1)?;
        let mut terms = terms();
        match field {
            "provider" => terms.provider = "other".into(),
            "model" => terms.model = "other".into(),
            "api_mode" => terms.api_mode = "other".into(),
            "reasoning_effort" => terms.reasoning_effort = "low".into(),
            _ => terms.limits.max_total_nanodollars -= 1,
        }
        terms.validate()?;
        enroll_terms(&mut fx, &authority, &terms)?;
        let store = fx.store()?;
        let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
        assert_eq!(cap.grant().budget_terms_digest, terms.computed_digest()?);
        assert!(
            store
                .check_campaign_inference_terms(&cap, &authority, &terms, now)
                .is_err(),
            "binding {field}"
        );
    }
    Ok(())
}

#[test]
fn terms_zero_and_inconsistent_limits_refuse_even_with_matching_digest() -> TestResult {
    let raw = serde_json::to_value(terms())?;
    for field in [
        "input_nanodollars_per_token",
        "output_nanodollars_per_token",
        "max_input_tokens_per_send",
        "max_output_tokens_per_send",
        "max_total_input_tokens",
        "max_total_output_tokens",
        "max_sends",
        "max_total_nanodollars",
    ] {
        let mut changed = raw.clone();
        changed["limits"][field] = json!(0);
        let terms: InferenceBudgetTermsV1 = serde_json::from_value(changed)?;
        let mut fx = Fixture::new()?;
        let authority = fx.authority(1)?;
        enroll_terms(&mut fx, &authority, &terms)?;
        let store = fx.store()?;
        let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
        assert!(terms.validate().is_err(), "invalid zero {field}");
        assert!(
            store
                .check_campaign_inference_terms(&cap, &authority, &terms, now)
                .is_err(),
            "zero {field}"
        );
    }
    let mut invalid = terms();
    invalid.limits.max_sends = 1025;
    assert!(invalid.validate().is_err());
    let mut invalid = terms();
    invalid.limits.max_total_input_tokens = 99;
    assert!(invalid.validate().is_err());
    let mut invalid = terms();
    invalid.limits.max_total_output_tokens = 19;
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn terms_arithmetic_overflow_and_noncanonical_large_integers_refuse() -> TestResult {
    let mut terms = terms();
    terms.limits.input_nanodollars_per_token = u64::MAX;
    assert!(terms.limits.quote_nanodollars().is_err());
    assert!(terms.validate().is_err());
    terms.limits.input_nanodollars_per_token = 100;
    terms.limits.max_total_nanodollars = 1_u64 << 53;
    assert!(terms.validate().is_err());
    let mut terms = self::terms();
    terms.limits.max_total_nanodollars = 19_999;
    assert!(terms.limits.quote_nanodollars().is_err());
    Ok(())
}

#[test]
fn terms_strict_bytes_refuse_duplicate_unknown_and_wrong_shapes() -> TestResult {
    let terms = terms();
    let encoded = serde_json::to_vec(&terms)?;
    assert_eq!(InferenceBudgetTermsV1::from_bytes(&encoded)?, terms);
    let mut raw = serde_json::to_value(&terms)?;
    raw["network_allowed"] = json!(true);
    assert!(InferenceBudgetTermsV1::from_bytes(&serde_json::to_vec(&raw)?).is_err());
    let mut raw = serde_json::to_value(&terms)?;
    raw["limits"]["refund_on_failure"] = json!(true);
    assert!(InferenceBudgetTermsV1::from_bytes(&serde_json::to_vec(&raw)?).is_err());
    let encoded = String::from_utf8(encoded)?;
    assert!(InferenceBudgetTermsV1::from_bytes(
        encoded
            .replacen('{', "{\"schema\":\"duplicate\",", 1)
            .as_bytes()
    )
    .is_err());
    assert!(InferenceBudgetTermsV1::from_bytes(b"[]").is_err());
    assert!(InferenceBudgetTermsV1::from_bytes(b"{}").is_err());
    assert!(InferenceBudgetTermsV1::from_bytes(b"null").is_err());
    assert!(InferenceBudgetTermsV1::from_bytes(&vec![b' '; 65_537]).is_err());
    let mut bad = terms.clone();
    bad.schema = "legacy-or-unknown".into();
    assert!(bad.validate().is_err());
    let mut bad = terms;
    bad.provider = "credential=example".into();
    assert!(bad.validate().is_err());
    Ok(())
}

#[test]
fn terms_stale_and_foreign_capabilities_remain_non_authorizing() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let store = fx.store()?;
    let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let foreign = Fixture::new()?;
    assert!(foreign
        .store()?
        .check_campaign_inference_terms(&cap, &authority, &terms, now)
        .is_err());
    assert!(store
        .check_campaign_inference_terms(&cap, &authority, &terms, || now() + TimeDelta::hours(1))
        .is_err());
    let _new_head = fx.authority(2)?;
    assert!(store
        .check_campaign_inference_terms(&cap, &authority, &terms, now)
        .is_err());
    assert!(store.read_campaign_funding_enrollment().is_ok());
    Ok(())
}

#[test]
fn terms_locked_validation_rechecks_expiry_and_clock_regression() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let store = fx.store()?;
    let cap = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut calls = 0;
    assert!(store
        .check_campaign_inference_terms(&cap, &authority, &terms, || {
            calls += 1;
            if calls == 1 {
                now()
            } else {
                now() + TimeDelta::hours(1)
            }
        })
        .is_err());
    assert_eq!(calls, 2);
    let mut calls = 0;
    assert!(store
        .check_campaign_inference_terms(&cap, &authority, &terms, || {
            calls += 1;
            if calls == 1 {
                now() + TimeDelta::seconds(1)
            } else {
                now()
            }
        })
        .is_err());
    assert_eq!(calls, 2);
    store.check_campaign_inference_terms(&cap, &authority, &terms, now)?;
    Ok(())
}

#[test]
fn terms_v1_flat_wire_shape_and_shared_quote_stay_compatible() -> TestResult {
    use recursive_agent_policy::InferenceBudgetGrantV1;
    let original = terms();
    let limits = serde_json::to_value(&original.limits)?;
    let mut raw = limits;
    let object = raw.as_object_mut().ok_or("limits must be an object")?;
    object.insert(
        "schema".into(),
        json!("recursive-agent.inference-budget/v1"),
    );
    object.insert(
        "root_operation_id".into(),
        json!(format!("v1:recursive-agent/run/v1:det:{}", "a".repeat(64))),
    );
    object.insert(
        "parent_control_permit_id".into(),
        json!(format!(
            "v1:recursive-agent/permit/v1:det:{}",
            "b".repeat(64)
        )),
    );
    object.insert("policy_version".into(), json!("policy:fixture"));
    object.insert("provider".into(), json!(original.provider));
    object.insert("model".into(), json!(original.model));
    object.insert("reasoning_effort".into(), json!(original.reasoning_effort));
    object.insert("tariff_digest".into(), json!(original.tariff_digest));
    object.insert("not_before".into(), json!(now()));
    object.insert("expires_at".into(), json!(now() + TimeDelta::seconds(60)));
    let v1: InferenceBudgetGrantV1 = serde_json::from_value(raw.clone())?;
    assert_eq!(v1.limits(), original.limits);
    assert_eq!(
        v1.limits().quote_nanodollars()?,
        original.limits.quote_nanodollars()?
    );
    assert_eq!(serde_json::to_value(&v1)?, raw);
    assert!(raw.get("limits").is_none());
    assert!(raw.get("api_mode").is_none());
    // New safe-canonical terms admission must not silently reinterpret legacy
    // V1 rate limits: its independent identity/lifetime/storage guards remain.
    let mut v1 = v1;
    v1.max_total_nanodollars = 1_u64 << 53;
    assert_eq!(v1.limits().quote_nanodollars()?, 20_000);
    let mut unknown = raw;
    unknown["limits"] = json!({});
    assert!(serde_json::from_value::<InferenceBudgetGrantV1>(unknown).is_err());
    Ok(())
}

fn controlled_family(
    authority: &NormalChatGrantAuthorityV1,
    conversation: &str,
) -> Result<
    (
        tempfile::TempDir,
        recursive_agent_policy::NormalChatControlledFamilyV1,
    ),
    Box<dyn std::error::Error>,
> {
    let root = tempfile::tempdir()?;
    let fd = File::open(root.path())?;
    let permits = DurablePermitStore::from_run_root_fd(&fd)?;
    let control = permits.open_normal_chat_session_control(authority, conversation, None, now)?;
    assert!(!control.permit().binding.effect.network_allowed);
    let family = recursive_agent_policy::FamilyAuthorityStore::from_normal_chat_session_control(
        &fd, authority, &control, now,
    )?;
    Ok((root, family))
}

#[test]
fn root_association_uses_real_issued_control_and_is_idempotent() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (root, family) = controlled_family(&authority, "conversation:root")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let first = store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    let repeated =
        store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, || {
            now() + TimeDelta::seconds(1)
        })?;
    assert_eq!(first, repeated);
    assert_eq!(store.read_campaign_monetary_root()?, first);
    assert_eq!(first.root.session.conversation_ref, "conversation:root");
    assert_eq!(
        first.root.family_grant.root_operation_id,
        first.root.session.run_id()?
    );
    assert_eq!(
        first.root.family_grant.child_run_ceiling.expires_at,
        now() + TimeDelta::minutes(5)
    );
    assert!(!root.path().join("inference-budget.v1.json").exists());
    assert!(!root.path().join("inference-budget.v2.json").exists());
    let permits = DurablePermitStore::from_run_root_fd(&File::open(root.path())?)?;
    let actual = permits
        .read_normal_chat_session_control_record()?
        .ok_or("missing real control")?;
    assert_eq!(
        first.root.family_grant.parent_control_permit_id,
        actual.permit.permit_id
    );
    assert!(!actual.permit.binding.effect.network_allowed);
    Ok(())
}

#[test]
fn root_association_session_rotation_cannot_select_a_fresh_root() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_a, first) = controlled_family(&authority, "conversation:first")?;
    let (_b, second) = controlled_family(&authority, "conversation:second")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let original = store.bind_campaign_monetary_root(&funding, &authority, &terms, &first, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &second, now)
        .is_err());
    assert_eq!(store.read_campaign_monetary_root()?, original);
    Ok(())
}

#[test]
fn root_association_same_session_in_another_directory_cannot_substitute() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_a, first) = controlled_family(&authority, "conversation:identical")?;
    let (_b, copied_identity) = controlled_family(&authority, "conversation:identical")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let original = store.bind_campaign_monetary_root(&funding, &authority, &terms, &first, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &copied_identity, now)
        .is_err());
    assert_eq!(store.read_campaign_monetary_root()?, original);
    Ok(())
}

#[test]
fn root_association_expired_control_cannot_be_extended_by_long_funding() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:expiry")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, || now()
            + TimeDelta::minutes(6))
        .is_err());
    assert!(store.read_campaign_monetary_root().is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-monetary-root.enrolled.v1")
        .exists());
    Ok(())
}

#[test]
fn root_association_revoked_or_closed_family_cannot_enroll() -> TestResult {
    for revoke_control in [false, true] {
        let mut fx = Fixture::new()?;
        let authority = fx.authority(1)?;
        let terms = terms();
        enroll_terms(&mut fx, &authority, &terms)?;
        let (root, family) = controlled_family(&authority, "conversation:revocation")?;
        let permits = DurablePermitStore::from_run_root_fd(&File::open(root.path())?)?;
        let control = permits
            .read_normal_chat_session_control_record()?
            .ok_or("missing control")?;
        if revoke_control {
            permits.revoke(
                &control.permit.permit_id,
                recursive_agent_policy::PermitRevocationReasonV1::Operator,
                now(),
            )?;
        } else {
            let plain = recursive_agent_policy::FamilyAuthorityStore::require_existing_from_dir_fd(
                &File::open(root.path())?,
                permits
                    .open_normal_chat_session_control(
                        &authority,
                        "conversation:revocation",
                        None,
                        now,
                    )?
                    .family_grant(),
            )?;
            plain.close_normal_chat_session(now())?;
        }
        let store = fx.store()?;
        let funding =
            store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
        assert!(store
            .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
            .is_err());
        assert!(store.read_campaign_monetary_root().is_err());
    }
    Ok(())
}

#[test]
fn root_association_missing_history_does_not_reinitialize_after_restart() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:lost")?;
    let funding =
        fx.store()?
            .load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    fx.store()?
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    fs::remove_file(fx.root.path().join("campaign-monetary-root.v1.json"))?;
    let reopened = fx.store()?;
    assert!(reopened.read_campaign_monetary_root().is_err());
    assert!(reopened
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    assert!(!fx
        .root
        .path()
        .join("campaign-monetary-root.v1.json")
        .exists());
    Ok(())
}

#[test]
fn root_association_anchor_detects_valid_canonical_record_tampering() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:tamper")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut record =
        store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    record.bound_at += TimeDelta::milliseconds(1);
    fs::write(
        fx.root.path().join("campaign-monetary-root.v1.json"),
        recursive_agent_contracts::jcs_canonical(&record)?,
    )?;
    assert!(
        store.read_campaign_monetary_root().is_err(),
        "changed canonical root association bypassed anchor"
    );
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    Ok(())
}

#[test]
fn root_association_history_survives_expiry_without_reopening_authority() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:history")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let record = store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, || now()
            + TimeDelta::hours(2))
        .is_err());
    assert_eq!(store.read_campaign_monetary_root()?, record);
    let _newer = fx.authority(2)?;
    assert_eq!(store.read_campaign_monetary_root()?, record);
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    Ok(())
}

#[test]
fn root_association_independent_enrollers_do_not_pick_two_roots() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_a, first) = controlled_family(&authority, "conversation:race-a")?;
    let (_b, second) = controlled_family(&authority, "conversation:race-b")?;
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> TestResult {
        let race = |family: &recursive_agent_policy::NormalChatControlledFamilyV1| -> bool {
            barrier.wait();
            let Ok(store) = fx.store() else {
                return false;
            };
            let Ok(funding) =
                store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)
            else {
                return false;
            };
            store
                .bind_campaign_monetary_root(&funding, &authority, &terms, family, now)
                .is_ok()
        };
        let a = scope.spawn(move || race(&first));
        let b = scope.spawn(move || race(&second));
        assert_ne!(
            a.join().map_err(|_| "race a panicked")?,
            b.join().map_err(|_| "race b panicked")?
        );
        Ok(())
    })?;
    assert!(fx.store()?.read_campaign_monetary_root().is_ok());
    Ok(())
}

#[test]
fn root_association_wrong_terms_and_stale_funding_cannot_publish() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:wrong")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut wrong = terms.clone();
    wrong.tariff_digest = ContentDigest::compute(b"different");
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &wrong, &family, now)
        .is_err());
    let _new = fx.authority(2)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    assert!(store.read_campaign_monetary_root().is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-monetary-root.enrolled.v1")
        .exists());
    Ok(())
}

#[test]
fn root_association_foreign_store_copy_is_not_a_new_enrollment() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:copy")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    let mut other = Fixture::new()?;
    let other_authority = other.authority(1)?;
    enroll_terms(&mut other, &other_authority, &terms)?;
    for name in [
        "campaign-monetary-root.v1.json",
        ".campaign-monetary-root.enrolled.v1",
    ] {
        fs::copy(fx.root.path().join(name), other.root.path().join(name))?;
    }
    assert!(other.store()?.read_campaign_monetary_root().is_err());
    Ok(())
}

#[test]
fn root_association_expiry_after_publication_keeps_immutable_fence() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:publish")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, || {
            if fx
                .root
                .path()
                .join("campaign-monetary-root.v1.json")
                .exists()
            {
                now() + TimeDelta::hours(1)
            } else {
                now()
            }
        })
        .is_err());
    let record = store.read_campaign_monetary_root()?;
    let (_other, replacement) = controlled_family(&authority, "conversation:replacement")?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &replacement, now)
        .is_err());
    assert_eq!(store.read_campaign_monetary_root()?, record);
    Ok(())
}

#[test]
fn root_association_all_lock_clock_samples_must_not_regress() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:clock")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    let mut calls = 0;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, || {
            calls += 1;
            if calls == 1 {
                now() + TimeDelta::seconds(1)
            } else {
                now()
            }
        })
        .is_err());
    assert!(calls >= 2);
    assert!(store.read_campaign_monetary_root().is_err());
    assert!(!fx
        .root
        .path()
        .join(".campaign-monetary-root.enrolled.v1")
        .exists());
    store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    Ok(())
}

#[test]
fn root_association_missing_anchor_or_malformed_state_cannot_reenroll() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (_root, family) = controlled_family(&authority, "conversation:anchor-lost")?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    store.bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)?;
    let anchor_path = fx.root.path().join(".campaign-monetary-root.enrolled.v1");
    let bytes = fs::read(&anchor_path)?;
    fs::remove_file(&anchor_path)?;
    assert!(store.read_campaign_monetary_root().is_err());
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    assert!(!anchor_path.exists());
    fs::write(&anchor_path, bytes)?;
    fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o600))?;
    fs::write(fx.root.path().join("campaign-monetary-root.v1.json"), b"{}")?;
    assert!(store.read_campaign_monetary_root().is_err());
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    Ok(())
}

#[test]
fn root_association_replaced_permit_directory_is_not_the_issued_control() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (root, family) = controlled_family(&authority, "conversation:dir-replaced")?;
    fs::rename(
        root.path().join("permits"),
        root.path().join("kept-permits"),
    )?;
    fs::create_dir(root.path().join("permits"))?;
    fs::set_permissions(
        root.path().join("permits"),
        fs::Permissions::from_mode(0o700),
    )?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    assert!(store.read_campaign_monetary_root().is_err());
    Ok(())
}

#[test]
fn root_association_missing_family_state_cannot_initialize_from_a_handle() -> TestResult {
    let mut fx = Fixture::new()?;
    let authority = fx.authority(1)?;
    let terms = terms();
    enroll_terms(&mut fx, &authority, &terms)?;
    let (root, family) = controlled_family(&authority, "conversation:family-lost")?;
    fs::remove_file(root.path().join("family-authority.json"))?;
    let store = fx.store()?;
    let funding = store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
    assert!(store
        .bind_campaign_monetary_root(&funding, &authority, &terms, &family, now)
        .is_err());
    assert!(!root.path().join("family-authority.json").exists());
    assert!(store.read_campaign_monetary_root().is_err());
    Ok(())
}

struct BankFixture {
    fx: Fixture,
    authority: NormalChatGrantAuthorityV1,
    terms: InferenceBudgetTermsV1,
    root: tempfile::TempDir,
}
impl BankFixture {
    fn new(initialize: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut fx = Fixture::new()?;
        let authority = fx.authority(1)?;
        let mut terms = terms();
        // Synthetic rates: exactly two full reservations fit the fixture cap.
        terms.limits.input_nanodollars_per_token = 10_000_000;
        terms.limits.output_nanodollars_per_token = 75_000_000;
        enroll_terms(&mut fx, &authority, &terms)?;
        let (root, controlled) = controlled_family(&authority, "conversation:bank")?;
        let store = fx.store()?;
        let funding =
            store.load_campaign_funding_from_path(&fx.path, &authority, &fx.expected, now)?;
        store.bind_campaign_monetary_root(&funding, &authority, &terms, &controlled, now)?;
        fs::write(
            fx.root.path().join("terms.json"),
            serde_json::to_vec(&terms)?,
        )?;
        let value = Self {
            fx,
            authority,
            terms,
            root,
        };
        if initialize {
            value.with_context(|family, context| {
                family.bind_campaign_inference_budget(context, now)
            })?;
        }
        Ok(value)
    }
    fn with_context<T>(
        &self,
        apply: impl FnOnce(
            &recursive_agent_policy::FamilyAuthorityStore,
            &recursive_agent_policy::CampaignInferenceContextV2<'_>,
        ) -> Result<T, recursive_agent_policy::PolicyError>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let grants = self.fx.store()?;
        let funding = grants.load_campaign_funding_from_path(
            &self.fx.path,
            &self.authority,
            &self.fx.expected,
            now,
        )?;
        let association = grants.read_campaign_monetary_root()?;
        let family = recursive_agent_policy::FamilyAuthorityStore::require_existing_from_dir_fd(
            &File::open(self.root.path())?,
            association.root.family_grant,
        )?;
        let context = recursive_agent_policy::CampaignInferenceContextV2 {
            grants: &grants,
            funding: &funding,
            authority: &self.authority,
            terms: &self.terms,
        };
        Ok(apply(&family, &context)?)
    }
    fn legacy(
        &self,
    ) -> Result<recursive_agent_policy::InferenceBudgetGrantV1, Box<dyn std::error::Error>> {
        let root = self
            .fx
            .store()?
            .read_campaign_monetary_root()?
            .root
            .family_grant;
        let mut raw = serde_json::to_value(&self.terms.limits)?;
        let object = raw.as_object_mut().ok_or("limits must be object")?;
        for (key, value) in [
            ("schema", json!("recursive-agent.inference-budget/v1")),
            ("root_operation_id", json!(root.root_operation_id)),
            (
                "parent_control_permit_id",
                json!(root.parent_control_permit_id),
            ),
            ("policy_version", json!(root.policy_version)),
            ("provider", json!(self.terms.provider)),
            ("model", json!(self.terms.model)),
            ("reasoning_effort", json!(self.terms.reasoning_effort)),
            ("tariff_digest", json!(self.terms.tariff_digest)),
            ("not_before", json!(now())),
            ("expires_at", json!(root.child_run_ceiling.expires_at)),
        ] {
            object.insert(key.into(), value);
        }
        Ok(serde_json::from_value(raw)?)
    }
}
fn bank_request(
    mark: char,
) -> Result<recursive_agent_policy::InferenceSendRequestV1, Box<dyn std::error::Error>> {
    Ok(recursive_agent_policy::InferenceSendRequestV1 {
        permit_id: recursive_agent_contracts::CurrentPermitId::try_new(format!(
            "v1:recursive-agent/permit/v1:det:{}",
            mark.to_string().repeat(64)
        ))?,
        request_digest: ContentDigest::compute(mark.to_string().as_bytes()),
        provider: "openai-codex".into(),
        model: "gpt-6-luna".into(),
        reasoning_effort: "xhigh".into(),
    })
}
#[test]
fn bank_v2_reservations_survive_reopen_and_enforce_cumulative_money() -> TestResult {
    let fx = BankFixture::new(true)?;
    let first = bank_request('c')?;
    let second = bank_request('d')?;
    let denied = bank_request('e')?;
    fx.with_context(|family, ctx| {
        family.bind_campaign_inference_budget(ctx, now)?;
        assert_eq!(
            family.reserve_campaign_inference(ctx, &first, now)?,
            family.reserve_campaign_inference(ctx, &first, now)?
        );
        Ok(())
    })?;
    fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &second, now)?;
        Ok(())
    })?;
    fx.with_context(|family, ctx| {
        assert!(
            family
                .reserve_campaign_inference(ctx, &denied, now)
                .is_err(),
            "cumulative campaign monetary ceiling was bypassed"
        );
        let status = family.campaign_inference_status(ctx.grants)?;
        assert_eq!(status.reserved_sends, 2);
        assert_eq!(status.reserved_nanodollars, 5_000_000_000);
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_dispatch_once_settlement_never_refunds_and_is_immutable() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    let ticket = fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &req, now)?;
        family.begin_campaign_inference(ctx, &req, now)
    })?;
    fx.with_context(|family, ctx| {
        assert!(family.begin_campaign_inference(ctx, &req, now).is_err());
        let outcome = recursive_agent_policy::InferenceSettlementV1::Observed {
            response_digest: ContentDigest::compute(b"observed"),
            input_tokens: 1,
            output_tokens: 1,
        };
        family.settle_campaign_inference(ctx.grants, &ticket, outcome.clone())?;
        family.settle_campaign_inference(ctx.grants, &ticket, outcome)?;
        assert!(family
            .settle_campaign_inference(
                ctx.grants,
                &ticket,
                recursive_agent_policy::InferenceSettlementV1::Unknown {
                    evidence_digest: ContentDigest::compute(b"changed")
                }
            )
            .is_err());
        assert_eq!(
            family
                .campaign_inference_status(ctx.grants)?
                .reserved_nanodollars,
            2_500_000_000
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_accounting_after_original_control_expiry_does_not_renew_execution() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &req, || now() + TimeDelta::minutes(6))?;
        Ok(())
    })?;
    let permits = DurablePermitStore::from_run_root_fd(&File::open(fx.root.path())?)?;
    assert!(permits
        .open_normal_chat_session_control(&fx.authority, "conversation:bank", None, || now()
            + TimeDelta::minutes(6))
        .is_err());
    fx.with_context(|family, ctx| {
        assert_eq!(
            family
                .read_campaign_inference(ctx.grants, &req)?
                .reserved_at,
            now() + TimeDelta::minutes(6)
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_exact_request_route_terms_and_foreign_root_refuse() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    fx.with_context(|family, ctx| {
        let mut wrong = req.clone();
        wrong.model = "other".into();
        assert!(family.reserve_campaign_inference(ctx, &wrong, now).is_err());
        family.reserve_campaign_inference(ctx, &req, now)?;
        let mut wrong = req.clone();
        wrong.request_digest = ContentDigest::compute(b"changed");
        assert!(family.reserve_campaign_inference(ctx, &wrong, now).is_err());
        assert!(family.begin_campaign_inference(ctx, &wrong, now).is_err());
        assert!(family.read_campaign_inference(ctx.grants, &wrong).is_err());
        let mut changed = ctx.terms.clone();
        changed.limits.input_nanodollars_per_token += 1;
        let bad = recursive_agent_policy::CampaignInferenceContextV2 {
            terms: &changed,
            ..*ctx
        };
        assert!(family.reserve_campaign_inference(&bad, &req, now).is_err());
        Ok(())
    })?;
    let other = BankFixture::new(true)?;
    let other_grants = other.fx.store()?;
    fx.with_context(|family, ctx| {
        assert!(family.campaign_inference_status(&other_grants).is_err());
        assert_eq!(
            family.campaign_inference_status(ctx.grants)?.reserved_sends,
            1
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_missing_state_or_binding_never_replenishes() -> TestResult {
    for name in ["inference-budget.v2.json", "inference-budget.v1.binding"] {
        let fx = BankFixture::new(true)?;
        let req = bank_request('c')?;
        fx.with_context(|family, ctx| {
            family.reserve_campaign_inference(ctx, &req, now)?;
            Ok(())
        })?;
        fs::remove_file(fx.root.path().join(name))?;
        fx.with_context(|family, ctx| {
            assert!(family.bind_campaign_inference_budget(ctx, now).is_err());
            assert!(family.campaign_inference_status(ctx.grants).is_err());
            Ok(())
        })?;
        assert!(!fx.root.path().join(name).exists());
    }
    Ok(())
}
#[test]
fn bank_v2_v1_are_mutually_exclusive_without_migration() -> TestResult {
    let fx = BankFixture::new(false)?;
    let legacy = fx.legacy()?;
    fx.with_context(|family, ctx| {
        family.bind_inference_budget(legacy.clone())?;
        assert!(family.bind_campaign_inference_budget(ctx, now).is_err());
        assert_eq!(family.inference_budget_status()?.reserved_sends, 0);
        Ok(())
    })?;
    assert!(!fx.root.path().join("inference-budget.v2.json").exists());
    let fx = BankFixture::new(true)?;
    let legacy = fx.legacy()?;
    fx.with_context(|family, _| {
        assert!(family.bind_inference_budget(legacy).is_err());
        Ok(())
    })?;
    assert!(!fx.root.path().join("inference-budget.v1.json").exists());
    Ok(())
}
#[test]
fn bank_v2_independent_handles_cannot_overreserve() -> TestResult {
    let fx = BankFixture::new(true)?;
    let barrier = std::sync::Barrier::new(4);
    let requests = ['c', 'd', 'e', 'f']
        .into_iter()
        .map(bank_request)
        .collect::<Result<Vec<_>, _>>()?;
    let successes = std::thread::scope(|scope| -> Result<usize, Box<dyn std::error::Error>> {
        let handles = requests
            .iter()
            .map(|req| {
                scope.spawn(|| {
                    barrier.wait();
                    fx.with_context(|family, ctx| family.reserve_campaign_inference(ctx, req, now))
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let mut n = 0;
        for h in handles {
            if h.join().map_err(|_| "reservation child panicked")? {
                n += 1;
            }
        }
        Ok(n)
    })?;
    assert_eq!(successes, 2);
    fx.with_context(|family, ctx| {
        assert_eq!(
            family
                .campaign_inference_status(ctx.grants)?
                .reserved_nanodollars,
            5_000_000_000
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_expiry_clock_refusal_preserves_readback_and_charge() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    fx.with_context(|family, ctx| {
        assert!(family
            .reserve_campaign_inference(ctx, &req, || now() + TimeDelta::hours(1))
            .is_err());
        let mut count = 0;
        assert!(family
            .reserve_campaign_inference(ctx, &req, || {
                count += 1;
                if count == 1 {
                    now() + TimeDelta::seconds(1)
                } else {
                    now()
                }
            })
            .is_err());
        assert_eq!(
            family.campaign_inference_status(ctx.grants)?.reserved_sends,
            1
        );
        assert_eq!(
            family
                .read_campaign_inference(ctx.grants, &req)?
                .reserved_at,
            now() + TimeDelta::seconds(1)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn bank_v2_revoked_funding_denies_new_work_but_settles_retained_evidence() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    let ticket = fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &req, now)?;
        family.begin_campaign_inference(ctx, &req, now)
    })?;
    let _new = fx.fx.authority(2)?;
    let grants = fx.fx.store()?;
    let association = grants.read_campaign_monetary_root()?;
    let family = recursive_agent_policy::FamilyAuthorityStore::require_existing_from_dir_fd(
        &File::open(fx.root.path())?,
        association.root.family_grant,
    )?;
    family.settle_campaign_inference(
        &grants,
        &ticket,
        recursive_agent_policy::InferenceSettlementV1::Unknown {
            evidence_digest: ContentDigest::compute(b"after revocation"),
        },
    )?;
    assert_eq!(family.campaign_inference_status(&grants)?.unknown_sends, 1);
    assert_eq!(
        family
            .campaign_inference_status(&grants)?
            .reserved_nanodollars,
        2_500_000_000
    );
    assert!(fx
        .with_context(|family, ctx| family.begin_campaign_inference(ctx, &req, now))
        .is_err());
    Ok(())
}
#[test]
fn bank_v2_malformed_mixed_and_foreign_ticket_cannot_close_history() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    let ticket = fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &req, now)?;
        family.begin_campaign_inference(ctx, &req, now)
    })?;
    let other = BankFixture::new(true)?;
    other.with_context(|family, ctx| {
        assert!(family
            .settle_campaign_inference(
                ctx.grants,
                &ticket,
                recursive_agent_policy::InferenceSettlementV1::Unknown {
                    evidence_digest: ContentDigest::compute(b"foreign")
                }
            )
            .is_err());
        Ok(())
    })?;
    let path = fx.root.path().join("inference-budget.v2.json");
    let original = fs::read(&path)?;
    fs::write(&path, b"{}")?;
    fx.with_context(|family, ctx| {
        assert!(family.bind_campaign_inference_budget(ctx, now).is_err());
        assert!(family.campaign_inference_status(ctx.grants).is_err());
        Ok(())
    })?;
    fs::write(&path, original)?;
    fs::write(fx.root.path().join("inference-budget.v1.json"), b"{}")?;
    fx.with_context(|family, ctx| {
        assert!(family.campaign_inference_status(ctx.grants).is_err());
        assert!(family.inference_budget_status().is_err());
        Ok(())
    })?;
    Ok(())
}
#[test]
fn bank_v2_last_clock_directory_replacement_refuses_ticket_and_keeps_charge() -> TestResult {
    let fx = BankFixture::new(true)?;
    let req = bank_request('c')?;
    fx.with_context(|family, ctx| {
        family.reserve_campaign_inference(ctx, &req, now)?;
        let mut calls = 0;
        assert!(family
            .begin_campaign_inference(ctx, &req, || {
                calls += 1;
                if calls == 2 {
                    let _ = fs::rename(
                        fx.root.path().join("permits"),
                        fx.root.path().join("kept-permits"),
                    );
                    let _ = fs::create_dir(fx.root.path().join("permits"));
                }
                now()
            })
            .is_err());
        assert_eq!(calls, 2);
        Ok(())
    })?;
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(fx.root.path().join("inference-budget.v2.json"))?)?;
    assert!(state["sends"][req.permit_id.as_str()]["dispatched_at"].is_string());
    Ok(())
}
#[test]
#[ignore = "subprocess entrypoint exercised by bank_v2_real_process_crash_remains_charged"]
fn bank_process_crash_child_entry() -> TestResult {
    let Some(path) = std::env::var_os("RI_CAMPAIGN_FIXTURE") else {
        return Ok(());
    };
    let home = PathBuf::from(path);
    let root = PathBuf::from(std::env::var_os("RI_CAMPAIGN_ROOT").ok_or("missing root")?);
    let grants = NormalChatEgressGrantStore::from_dir_fd(&File::open(&home)?)?;
    let authority = grants.load_from_path(&home.join("egress.json"), HOME, now())?;
    let raw: CampaignFundingGrantV1 =
        serde_json::from_slice(&fs::read(home.join("funding.json"))?)?;
    let terms = InferenceBudgetTermsV1::from_bytes(&fs::read(home.join("terms.json"))?)?;
    let expected = CampaignFundingExpectationV1 {
        mission_contract_ref: raw.mission_contract_ref.clone(),
        kanban_root_task_ref: raw.kanban_root_task_ref.clone(),
        ares_home_digest: raw.ares_home_digest.clone(),
        provider_identity: raw.provider_identity.clone(),
        model_ref: raw.model_ref.clone(),
        api_mode: raw.api_mode.clone(),
        reasoning_effort: raw.reasoning_effort.clone(),
        budget_terms_digest: raw.budget_terms_digest.clone(),
        max_total_nanodollars: raw.max_total_nanodollars,
    };
    let funding = grants.load_campaign_funding_from_path(
        &home.join("funding.json"),
        &authority,
        &expected,
        now,
    )?;
    let family = recursive_agent_policy::FamilyAuthorityStore::require_existing_from_dir_fd(
        &File::open(root)?,
        grants.read_campaign_monetary_root()?.root.family_grant,
    )?;
    let ctx = recursive_agent_policy::CampaignInferenceContextV2 {
        grants: &grants,
        funding: &funding,
        authority: &authority,
        terms: &terms,
    };
    let req = bank_request('c')?;
    family.reserve_campaign_inference(&ctx, &req, now)?;
    let _ticket = family.begin_campaign_inference(&ctx, &req, now)?;
    std::process::exit(73)
}
#[test]
fn bank_v2_real_process_crash_remains_charged() -> TestResult {
    let fx = BankFixture::new(true)?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "bank_process_crash_child_entry",
            "--ignored",
            "--test-threads=1",
        ])
        .env("RI_CAMPAIGN_FIXTURE", fx.fx.root.path())
        .env("RI_CAMPAIGN_ROOT", fx.root.path())
        .output()?;
    assert_eq!(
        child.status.code(),
        Some(73),
        "child did not reach durable budget handoff: {:?}",
        child
    );
    let req = bank_request('c')?;
    fx.with_context(|family, ctx| {
        let before = fs::read(fx.root.path().join("inference-budget.v2.json"))
            .map_err(recursive_agent_policy::PolicyError::from)?;
        let read = family.read_campaign_inference(ctx.grants, &req)?;
        assert!(read.dispatched_at.is_some());
        assert!(read.settlement.is_none());
        assert_eq!(
            before,
            fs::read(fx.root.path().join("inference-budget.v2.json"))
                .map_err(recursive_agent_policy::PolicyError::from)?
        );
        assert!(family.begin_campaign_inference(ctx, &req, now).is_err());
        let status = family.campaign_inference_status(ctx.grants)?;
        assert_eq!(status.unsettled_dispatches, 1);
        assert_eq!(status.reserved_nanodollars, 2_500_000_000);
        Ok(())
    })?;
    Ok(())
}
