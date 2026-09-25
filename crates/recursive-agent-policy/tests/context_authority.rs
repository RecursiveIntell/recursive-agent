use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{Signer, SigningKey};
use recursive_agent_contracts::{content_digest, jcs_canonical, ToolCallSpecV1};
use recursive_agent_policy::*;
use std::fs::File;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

struct Fixture {
    root: tempfile::TempDir,
    store: DurablePermitStore,
    configuration: ContextAuthorityConfigurationV1,
    access: ContextAuthorityAccess,
    controller: SigningKey,
    approver: SigningKey,
    verifier: ProductionApprovalVerifierV1,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = DurablePermitStore::from_dir_fd(&File::open(root.path())?)?;
        let controller = SigningKey::from_bytes(&[3; 32]);
        let approver = SigningKey::from_bytes(&[7; 32]);
        let verifier = ProductionApprovalVerifierV1::from_public_key_bytes(
            "desktop".into(),
            approver.verifying_key().to_bytes(),
        )?;
        let configuration = ContextAuthorityConfigurationV1 {
            schema: ContextAuthoritySchemaV1::V1,
            incarnation: store.initialize_context_authority()?,
            revision: 1,
            approval_verifier: verifier.context_authority_digest()?,
            grants: vec![ContextScopeGrantV1 {
                scope: ContextScopeV1 {
                    store: content_digest(&"ares-store")?,
                    profile: "work".into(),
                    root: "conversation-root".into(),
                },
                controller_public_key: controller.verifying_key().to_bytes(),
                actor: ActorPrincipalV1::try_new("desktop:operator")?,
                policy_version: "policy-v1".into(),
                policy_digest: content_digest(&"policy-v1")?,
                write_root: PRODUCTION_PERMIT_TARGET_ROOT.into(),
                initial_head: ContextHeadV1 {
                    context: "parent".into(),
                    generation: 1,
                    mode: ContextAdmissionModeV1::Active,
                },
                not_before: now(),
                expires_at: now() + TimeDelta::hours(1),
                max_effects: 8,
                max_transitions: 20,
                previous_grant: None,
            }],
        };
        let access = store.enroll_context_authority(&configuration)?;
        Ok(Self {
            root,
            store,
            configuration,
            access,
            controller,
            approver,
            verifier,
        })
    }

    fn authority(&self) -> Result<ContextAuthorityBindingV1, Box<dyn std::error::Error>> {
        Ok(self
            .store
            .read_context_authority(
                &self.configuration.incarnation,
                &self.configuration.grants[0].scope,
            )?
            .authority)
    }

    fn witness(&self, id: &str) -> Result<ProductionApprovalWitnessV1, Box<dyn std::error::Error>> {
        let mut witness = ProductionApprovalWitnessV1 {
            approval_id: id.into(),
            mission_ref: "mission".into(),
            target_ref: "output".into(),
            call: ToolCallSpecV1 {
                tool: "write_file".into(),
                args: serde_json::json!({"path":format!("{PRODUCTION_PERMIT_TARGET_ROOT}/out.txt"), "content":"approved"}),
                frozen_clock: None,
            },
            actor: self.configuration.grants[0].actor.clone(),
            effect: EffectScopeV1 {
                scope_name: format!("production-per-call:{id}"),
                read_roots: vec![],
                write_roots: vec![PRODUCTION_PERMIT_TARGET_ROOT.into()],
                network_allowed: false,
            },
            budget: PermitBudgetV1 {
                max_wall_time_ms: 1000,
                max_output_bytes: 4096,
                max_artifact_bytes: 8192,
            },
            policy_version: self.configuration.grants[0].policy_version.clone(),
            issued_at: now(),
            not_before: now(),
            expires_at: now() + TimeDelta::seconds(60),
            retry: RetryPolicyV1::NoRetry,
            delegation: DelegationPolicyV1::Forbidden,
            outcome_policy: OutcomePolicyV1::TerminalQuarantine,
            key_id: "desktop".into(),
            signature: vec![],
        };
        let mut value = serde_json::to_value(&witness)?;
        value
            .as_object_mut()
            .ok_or("witness object")?
            .remove("signature");
        witness.signature = self
            .approver
            .sign(&jcs_canonical(&value)?)
            .to_bytes()
            .to_vec();
        Ok(witness)
    }

    fn context(
        &self,
        witness: &ProductionApprovalWitnessV1,
    ) -> Result<ContextCallBindingV1, Box<dyn std::error::Error>> {
        let mut context = ContextCallBindingV1 {
            authority: self.authority()?,
            witness_digest: content_digest(witness)?,
            signature: vec![],
        };
        context.signature = self
            .controller
            .sign(&context.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(context)
    }

    fn transition(
        &self,
        id: &str,
        action: ContextTransitionActionV1,
    ) -> Result<ContextTransitionRequestV1, Box<dyn std::error::Error>> {
        let mut request = ContextTransitionRequestV1 {
            authority: self.authority()?,
            transition: content_digest(&id)?,
            action,
            signature: vec![],
        };
        request.signature = self
            .controller
            .sign(&request.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(request)
    }

    fn issue(
        &self,
        id: &str,
    ) -> Result<(ScopedExecutionPermitV1, ProductionApprovalWitnessV1), Box<dyn std::error::Error>>
    {
        let witness = self.witness(id)?;
        let permit = self.store.issue_scoped_external_permit(
            &self.access,
            &self.verifier,
            &witness,
            &self.context(&witness)?,
            now,
        )?;
        Ok((permit, witness))
    }

    fn retire_activate(&self) -> TestResult {
        let request = self.transition(
            "retirement",
            ContextTransitionActionV1::Retire {
                successor_context: "child".into(),
            },
        )?;
        let receipt = self
            .store
            .transition_context_authority(&self.access, &request, now, None)?;
        let activation = self.transition(
            "activation",
            ContextTransitionActionV1::Activate {
                retirement_digest: receipt.receipt_digest,
            },
        )?;
        self.store
            .transition_context_authority(&self.access, &activation, now, None)?;
        Ok(())
    }
}

#[test]
fn retirement_seals_old_calls_and_preserves_consumed_obligations_after_restart() -> TestResult {
    let f = Fixture::new()?;
    let (consumed, call) = f.issue("consumed")?;
    let (unconsumed, call2) = f.issue("not-consumed")?;
    let preflight = f.store.consume_scoped_external_permit(
        &f.access,
        &f.verifier,
        &consumed,
        &call.call,
        now,
    )?;
    let request = f.transition(
        "retire",
        ContextTransitionActionV1::Retire {
            successor_context: "child".into(),
        },
    )?;
    let receipt = f
        .store
        .transition_context_authority(&f.access, &request, now, None)?;
    assert_eq!(receipt.consumed.len(), 1);
    assert_eq!(
        receipt.consumed[0].preflight_receipt_digest,
        preflight.receipt_digest
    );
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &f.verifier, &unconsumed, &call2.call, now)
        .is_err());
    let reopened = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
    assert_eq!(
        reopened.initialize_context_authority()?,
        f.configuration.incarnation
    );
    assert_eq!(
        reopened.read_context_transition(&request)?,
        Some(receipt.clone())
    );
    assert_eq!(
        reopened.transition_context_authority(
            &f.access,
            &request,
            || now() + TimeDelta::seconds(1),
            None
        )?,
        receipt
    );
    let report = ReportedEffectOutcomeV1 {
        state: ReportedEffectStateV1::OutcomeAmbiguous,
        duration_ms: 1,
        error_type: Some("ack_lost".into()),
    };
    let outcome = reopened.settle_scoped_external_permit(
        &consumed,
        &preflight.receipt_digest,
        report.clone(),
        now,
    )?;
    assert_eq!(
        reopened.settle_scoped_external_permit(
            &consumed,
            &preflight.receipt_digest,
            report,
            || now() + TimeDelta::seconds(3)
        )?,
        outcome
    );
    assert_eq!(
        reopened.read_scoped_external_permit(&consumed)?.outcome,
        Some(outcome)
    );
    let activation = f.transition(
        "activate",
        ContextTransitionActionV1::Activate {
            retirement_digest: receipt.receipt_digest,
        },
    )?;
    let active = reopened.transition_context_authority(&f.access, &activation, now, None)?;
    assert_eq!(active.consumed.len(), 1); // unknown remains an obligation
    assert!(reopened
        .consume_scoped_external_permit(&f.access, &f.verifier, &consumed, &call.call, now)
        .is_err());
    Ok(())
}

#[test]
fn approval_cannot_be_wrapped_again_in_a_new_generation_or_scope() -> TestResult {
    let mut f = Fixture::new()?;
    let (permit, witness) = f.issue("one-use")?;
    assert_eq!(
        f.store.issue_scoped_external_permit(
            &f.access,
            &f.verifier,
            &witness,
            &permit.context,
            now
        )?,
        permit
    );
    f.retire_activate()?;
    assert!(f
        .store
        .issue_scoped_external_permit(&f.access, &f.verifier, &witness, &f.context(&witness)?, now)
        .is_err());
    let mut another = f.configuration.grants[0].clone();
    another.scope.root = "other-root".into();
    f.configuration.grants.push(another.clone());
    f.configuration.revision += 1;
    f.access = f.store.enroll_context_authority(&f.configuration)?;
    let mut context = f.context(&witness)?;
    context.authority = f
        .store
        .read_context_authority(&f.configuration.incarnation, &another.scope)?
        .authority;
    context.signature = f
        .controller
        .sign(&context.signing_bytes()?)
        .to_bytes()
        .to_vec();
    assert!(f
        .store
        .issue_scoped_external_permit(&f.access, &f.verifier, &witness, &context, now)
        .is_err());
    Ok(())
}

#[test]
fn every_scope_coordinate_and_controller_signature_is_checked() -> TestResult {
    let f = Fixture::new()?;
    let witness = f.witness("scope-tests")?;
    let context = f.context(&witness)?;
    for variant in 0..8 {
        let mut changed = context.clone();
        match variant {
            0 => changed.authority.scope.profile = "other".into(),
            1 => changed.authority.scope.root = "other".into(),
            2 => changed.authority.scope.store = content_digest(&"other")?,
            3 => changed.authority.incarnation = content_digest(&"other")?,
            4 => changed.authority.policy_digest = content_digest(&"other")?,
            5 => changed.authority.head.generation += 1,
            6 => changed.witness_digest = content_digest(&"other")?,
            _ => {}
        }
        let key = if variant == 7 {
            SigningKey::from_bytes(&[9; 32])
        } else {
            f.controller.clone()
        };
        changed.signature = key.sign(&changed.signing_bytes()?).to_bytes().to_vec();
        assert!(
            f.store
                .issue_scoped_external_permit(&f.access, &f.verifier, &witness, &changed, now)
                .is_err(),
            "accepted variant {variant}"
        );
    }
    assert!(f
        .store
        .issue_scoped_external_permit(&f.access, &f.verifier, &witness, &context, now)
        .is_ok());
    Ok(())
}

#[test]
fn initialization_fences_all_legacy_entrypoints_and_preexisting_approvals() -> TestResult {
    let f = Fixture::new()?;
    let root = tempfile::tempdir()?;
    let legacy = DurablePermitStore::from_dir_fd(&File::open(root.path())?)?;
    let witness = f.witness("legacy")?;
    let binding = f.verifier.verify_and_build_binding(&witness, now())?;
    let permit = legacy.issue(&binding, now())?;
    let incarnation = legacy.initialize_context_authority()?;
    assert!(legacy.issue(&binding, now()).is_err());
    assert!(legacy.consume(&permit.permit_id, &binding, now()).is_err());
    assert!(legacy
        .consume_with_preflight(&permit.permit_id, &binding, now)
        .is_err());
    let reopened = DurablePermitStore::from_dir_fd(&File::open(root.path())?)?;
    assert!(reopened
        .consume_with_interruption(&permit.permit_id, &binding, now(), None)
        .is_err());
    let mut configuration = f.configuration.clone();
    configuration.incarnation = incarnation.clone();
    let access = reopened.enroll_context_authority(&configuration)?;
    let mut context = f.context(&witness)?;
    context.authority.incarnation = incarnation;
    context.signature = f
        .controller
        .sign(&context.signing_bytes()?)
        .to_bytes()
        .to_vec();
    assert!(reopened
        .issue_scoped_external_permit(&access, &f.verifier, &witness, &context, now)
        .is_err());
    assert_eq!(
        reopened.state(&permit.permit_id)?.state,
        PermitStateV1::Issued
    );
    Ok(())
}

#[test]
fn grant_revocation_policy_change_and_key_rotation_preserve_charges() -> TestResult {
    let mut f = Fixture::new()?;
    let (permit, witness) = f.issue("old-policy")?;
    let old_access = f.access.clone();
    let old_config = f.configuration.clone();
    let mut revoked = f.configuration.clone();
    revoked.revision = 2;
    revoked.grants.clear();
    f.store.enroll_context_authority(&revoked)?;
    assert!(f
        .store
        .consume_scoped_external_permit(&old_access, &f.verifier, &permit, &witness.call, now)
        .is_err());
    assert!(f.store.enroll_context_authority(&old_config).is_err());
    f.configuration.revision = 3;
    f.configuration.grants[0].previous_grant = Some(content_digest(&old_config.grants[0])?);
    f.configuration.grants[0].policy_version = "policy-v2".into();
    f.configuration.grants[0].policy_digest = content_digest(&"policy-v2")?;
    f.configuration.grants[0].max_effects = 2;
    f.controller = SigningKey::from_bytes(&[11; 32]);
    f.configuration.grants[0].controller_public_key = f.controller.verifying_key().to_bytes();
    f.access = f.store.enroll_context_authority(&f.configuration)?;
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &f.verifier, &permit, &witness.call, now)
        .is_err());
    f.issue("new-policy")?;
    assert!(f.issue("over-budget").is_err());
    let snapshot = f.store.read_context_authority(
        &f.configuration.incarnation,
        &f.configuration.grants[0].scope,
    )?;
    assert_eq!(snapshot.effects_charged, 2);
    Ok(())
}

#[test]
fn retirement_is_atomic_at_every_write_boundary_and_exact_retry_does_not_recharge() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let f = Fixture::new()?;
        let request = f.transition(
            "retire",
            ContextTransitionActionV1::Retire {
                successor_context: "child".into(),
            },
        )?;
        assert!(f
            .store
            .transition_context_authority(&f.access, &request, now, Some(stage))
            .is_err());
        let reopened = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
        let before = reopened.read_context_authority(
            &f.configuration.incarnation,
            &f.configuration.grants[0].scope,
        )?;
        let receipt = reopened.read_context_transition(&request)?;
        assert_eq!(before.transitions_charged, u64::from(receipt.is_some()));
        assert_eq!(
            before.authority.head.generation,
            1 + u64::from(receipt.is_some())
        );
        let committed = reopened.transition_context_authority(&f.access, &request, now, None)?;
        assert_eq!(
            reopened.transition_context_authority(&f.access, &request, now, None)?,
            committed
        );
        assert_eq!(
            reopened
                .read_context_authority(
                    &f.configuration.incarnation,
                    &f.configuration.grants[0].scope
                )?
                .transitions_charged,
            1
        );
        let mut conflicting = request.clone();
        conflicting.action = ContextTransitionActionV1::Retire {
            successor_context: "different".into(),
        };
        assert!(reopened.read_context_transition(&conflicting).is_err());
    }
    Ok(())
}

#[test]
fn consume_retirement_race_has_one_serial_order_and_never_loses_obligation() -> TestResult {
    for _ in 0..12 {
        let f = Fixture::new()?;
        let (permit, witness) = f.issue("race")?;
        let request = f.transition(
            "race-retire",
            ContextTransitionActionV1::Retire {
                successor_context: "child".into(),
            },
        )?;
        let store = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
        let access = f.access.clone();
        let verifier = f.verifier.clone();
        let task = std::thread::spawn(move || {
            store.consume_scoped_external_permit(&access, &verifier, &permit, &witness.call, now)
        });
        let receipt = f
            .store
            .transition_context_authority(&f.access, &request, now, None)?;
        let result = task.join().map_err(|_| "consumer panicked")?;
        assert_eq!(receipt.consumed.len(), usize::from(result.is_ok()));
    }
    Ok(())
}

#[test]
fn consume_rechecks_expiry_after_lock_wait_and_final_validation() -> TestResult {
    use std::os::fd::AsFd;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let f = Fixture::new()?;
    let (permit, witness) = f.issue("expiry")?;
    let calls = AtomicUsize::new(0);
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &f.verifier, &permit, &witness.call, || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                now()
            } else {
                witness.expires_at
            }
        })
        .is_err());
    assert!(f
        .store
        .read_scoped_external_permit(&permit)?
        .preflight
        .is_none());
    let held = File::open(f.root.path().join(".permit.lock"))?;
    rustix::fs::flock(held.as_fd(), rustix::fs::FlockOperation::LockExclusive)?;
    let sampled = Arc::new(AtomicUsize::new(0));
    let clock_seen = Arc::clone(&sampled);
    let store = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
    let access = f.access.clone();
    let verifier = f.verifier.clone();
    let (started, waiting) = std::sync::mpsc::channel();
    let task = std::thread::spawn(move || {
        let _ = started.send(());
        store.consume_scoped_external_permit(&access, &verifier, &permit, &witness.call, || {
            clock_seen.fetch_add(1, Ordering::SeqCst);
            witness.expires_at
        })
    });
    waiting.recv_timeout(std::time::Duration::from_secs(2))?;
    assert_eq!(sampled.load(Ordering::SeqCst), 0);
    rustix::fs::flock(held.as_fd(), rustix::fs::FlockOperation::Unlock)?;
    assert!(task.join().map_err(|_| "consumer panicked")?.is_err());
    assert!(sampled.load(Ordering::SeqCst) > 0);
    Ok(())
}

#[test]
fn copied_store_cannot_claim_original_incarnation() -> TestResult {
    let f = Fixture::new()?;
    let substituted = tempfile::tempdir()?;
    std::fs::copy(
        f.root.path().join("context-authority-v1.json"),
        substituted.path().join("context-authority-v1.json"),
    )?;
    let store = DurablePermitStore::from_dir_fd(&File::open(substituted.path())?)?;
    assert!(store.initialize_context_authority().is_err());
    assert!(store.enroll_context_authority(&f.configuration).is_err());
    assert!(store
        .read_context_authority(
            &f.configuration.incarnation,
            &f.configuration.grants[0].scope
        )
        .is_err());
    Ok(())
}

#[test]
fn legacy_consumed_effect_cannot_disappear_into_empty_scoped_inventory() -> TestResult {
    let f = Fixture::new()?;
    let root = tempfile::tempdir()?;
    let store = DurablePermitStore::from_dir_fd(&File::open(root.path())?)?;
    let witness = f.witness("legacy-consumed")?;
    let binding = f.verifier.verify_and_build_binding(&witness, now())?;
    let permit = store.issue(&binding, now())?;
    let preflight = store.consume_with_preflight(&permit.permit_id, &binding, now)?;
    assert!(store.initialize_context_authority().is_err());
    store.record_reported_outcome(
        &permit.permit_id,
        &preflight.receipt_digest,
        ReportedEffectOutcomeV1 {
            state: ReportedEffectStateV1::OutcomeAmbiguous,
            duration_ms: 1,
            error_type: Some("unknown".into()),
        },
        now(),
    )?;
    assert!(store.initialize_context_authority().is_err());
    assert_eq!(
        store
            .read_external_permit(&permit.permit_id, &binding, Some(&preflight.receipt_digest))?
            .preflight,
        Some(preflight)
    );
    Ok(())
}

#[test]
fn canonical_projection_damage_cannot_restore_old_admission() -> TestResult {
    let f = Fixture::new()?;
    let (permit, witness) = f.issue("old")?;
    let old_head = f.authority()?.head;
    f.retire_activate()?;
    let path = f.root.path().join("context-authority-v1.json");
    let original = std::fs::read(&path)?;
    for variant in 0..4 {
        let mut raw: serde_json::Value = serde_json::from_slice(&original)?;
        let scope = raw["scopes"]
            .as_object_mut()
            .ok_or("scopes")?
            .values_mut()
            .next()
            .ok_or("scope")?;
        match variant {
            0 => scope["head"] = serde_json::to_value(&old_head)?,
            1 => scope["retirement_digest"] = serde_json::to_value(content_digest(&"wrong")?)?,
            2 => scope["grant"]["controller_public_key"] = serde_json::to_value([0_u8; 32])?,
            _ => scope["effects"] = serde_json::json!(0),
        }
        std::fs::write(&path, jcs_canonical(&raw)?)?;
        let reopened = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
        assert!(reopened
            .read_context_authority(
                &f.configuration.incarnation,
                &f.configuration.grants[0].scope
            )
            .is_err());
        assert!(reopened
            .consume_scoped_external_permit(&f.access, &f.verifier, &permit, &witness.call, now)
            .is_err());
    }
    std::fs::write(&path, &original)?;
    let mut config = f.configuration.clone();
    config.revision += 1;
    config.grants.clear();
    f.store.enroll_context_authority(&config)?;
    let mut raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    raw["scopes"]
        .as_object_mut()
        .ok_or("scopes")?
        .values_mut()
        .next()
        .ok_or("scope")?["active"] = serde_json::json!(true);
    std::fs::write(&path, jcs_canonical(&raw)?)?;
    assert!(f
        .store
        .read_context_authority(
            &f.configuration.incarnation,
            &f.configuration.grants[0].scope
        )
        .is_err());
    Ok(())
}

#[test]
fn removed_or_rotated_approval_verifier_does_not_admit_an_issued_effect() -> TestResult {
    let f = Fixture::new()?;
    let (permit, witness) = f.issue("key-rotation")?;
    let replaced = SigningKey::from_bytes(&[12; 32]);
    let verifier = ProductionApprovalVerifierV1::from_public_key_bytes(
        "desktop".into(),
        replaced.verifying_key().to_bytes(),
    )?;
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &verifier, &permit, &witness.call, now)
        .is_err());
    assert!(f
        .store
        .read_scoped_external_permit(&permit)?
        .preflight
        .is_none());
    let renamed = ProductionApprovalVerifierV1::from_public_key_bytes(
        "different-enrollment".into(),
        f.approver.verifying_key().to_bytes(),
    )?;
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &renamed, &permit, &witness.call, now)
        .is_err());
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &f.verifier, &permit, &witness.call, now)
        .is_ok());
    Ok(())
}

#[test]
fn approval_key_supersession_fences_a_still_running_old_daemon() -> TestResult {
    let f = Fixture::new()?;
    let (permit, witness) = f.issue("old-daemon")?;
    let second = DurablePermitStore::from_dir_fd(&File::open(f.root.path())?)?;
    let key = SigningKey::from_bytes(&[18; 32]);
    let replacement = ProductionApprovalVerifierV1::from_public_key_bytes(
        "desktop-new".into(),
        key.verifying_key().to_bytes(),
    )?;
    let mut config = f.configuration.clone();
    config.revision += 1;
    config.approval_verifier = replacement.context_authority_digest()?;
    let new_access = second.enroll_context_authority(&config)?;
    assert!(f
        .store
        .consume_scoped_external_permit(&f.access, &f.verifier, &permit, &witness.call, now)
        .is_err());
    assert!(second
        .consume_scoped_external_permit(&new_access, &f.verifier, &permit, &witness.call, now)
        .is_err());
    assert!(second
        .consume_scoped_external_permit(&new_access, &replacement, &permit, &witness.call, now)
        .is_err());
    assert!(f.store.enroll_context_authority(&f.configuration).is_err());
    assert!(second
        .read_scoped_external_permit(&permit)?
        .preflight
        .is_none());
    Ok(())
}
