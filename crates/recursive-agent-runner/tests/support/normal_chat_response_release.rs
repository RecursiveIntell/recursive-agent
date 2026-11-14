use super::*;
use recursive_agent_runner::RuntimeNormalChatBeginV2;
use std::cell::Cell;

#[test]
fn response_release_consumes_fresh_and_duplicate_begin_is_status_only() -> TestResult {
    // Positive publication needs room for full-workspace I/O contention. Tight
    // expiry/deadline rejection has separate unchanged negative witnesses.
    let fx = Fixture::with_send_window(30_000)?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut req = request(&fx, &session, "intent:release-one")?;
    req.operation.budget.max_wall_time_ms = 30_000;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("expected fresh".into()),
    };
    let expiry = fresh.expires_at();
    let preflight = fresh.preflight_digest().clone();
    let called = Cell::new(0);
    service.release_normal_chat_attempt(*fresh, |dispatch| {
        called.set(called.get() + 1);
        assert_eq!(
            dispatch.attempt().dispatch_intent_ref,
            req.dispatch_intent_ref
        );
        assert_eq!(dispatch.preflight_digest(), &preflight);
        assert_eq!(dispatch.expires_at(), expiry);
        assert!(dispatch.admitted_at() < expiry);
        Ok(())
    })?;
    assert_eq!(called.get(), 1);
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    Ok(())
}
#[test]
fn response_release_rejects_expired_original_lease_without_delivery_or_refund() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:expiry")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let before = std::fs::read(session.run_dir().join("family-authority.json"))?;
    fx.clock.0.store(1001, Ordering::SeqCst);
    let called = Cell::new(0);
    assert!(service
        .release_normal_chat_attempt(*fresh, |_| {
            called.set(called.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(called.get(), 0);
    assert_eq!(
        before,
        std::fs::read(session.run_dir().join("family-authority.json"))?
    );
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    Ok(())
}
#[test]
fn response_release_write_failure_does_not_restore_authority() -> TestResult {
    // Positive publication needs room for full-workspace I/O contention. Tight
    // expiry/deadline rejection has separate unchanged negative witnesses.
    let fx = Fixture::with_send_window(30_000)?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut req = request(&fx, &session, "intent:lost-ack")?;
    req.operation.budget.max_wall_time_ms = 30_000;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let calls = Cell::new(0);
    let result = service.release_normal_chat_attempt(*fresh, |_| -> Result<(), std::io::Error> {
        calls.set(calls.get() + 1);
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    Ok(())
}
#[test]
fn response_release_refuses_changed_child_inventory_before_delivery() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:inventory")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    std::fs::write(
        fresh.child_run_dir().join("artifacts/unrelated"),
        b"invalid",
    )?;
    let calls = Cell::new(0);
    assert!(service
        .release_normal_chat_attempt(*fresh, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}
#[test]
fn response_release_final_observer_cannot_rewrite_native_or_parent_history() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:observer")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let calls = Cell::new(0);
    let file = fresh.child_run_dir().join("chain.meta");
    let changed = std::cell::RefCell::new(Ok(()));
    let result = service.release_normal_chat_attempt_with_observer(
        *fresh,
        || {
            *changed.borrow_mut() = std::fs::write(file, b"{}");
        },
        |_| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    );
    changed.into_inner()?;
    assert!(result.is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}

#[test]
fn response_release_preserves_final_begin_clock_floor() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:clock-floor")?;
    let fresh =
        match service.begin_normal_chat_attempt_with_observer(&session, &req, None, || {
            fx.clock.0.store(200, Ordering::SeqCst);
        })? {
            RuntimeNormalChatBeginV2::Fresh(v) => v,
            _ => return Err("not fresh".into()),
        };
    // Later than preflight, earlier than the last accepted Begin sample.
    fx.clock.0.store(150, Ordering::SeqCst);
    let calls = Cell::new(0);
    assert!(service
        .release_normal_chat_attempt(*fresh, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}

#[test]
fn response_release_charges_verification_and_sink_to_absolute_deadline() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut req = request(&fx, &session, "intent:absolute-deadline")?;
    req.operation.budget.max_wall_time_ms = 100;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let calls = Cell::new(0);
    assert!(service
        .release_normal_chat_attempt_with_observer(
            *fresh,
            || std::thread::sleep(std::time::Duration::from_millis(120)),
            |_| {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}

#[test]
fn response_release_native_clock_regression_cannot_publish_before_error() -> TestResult {
    struct ArmedClock {
        armed: std::sync::atomic::AtomicBool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Clock for ArmedClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            let millis = if !self.armed.load(Ordering::SeqCst) {
                0
            } else if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                300
            } else {
                200
            };
            start() + chrono::TimeDelta::milliseconds(millis)
        }
    }
    let fx = Fixture::new()?;
    let clock = std::sync::Arc::new(ArmedClock {
        armed: std::sync::atomic::AtomicBool::new(false),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let service =
        runtime(fx.root.path(), clock.clone())?.with_normal_chat_egress_grant(fx.authority.clone());
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:native-clock")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(v) => v,
        _ => return Err("not fresh".into()),
    };
    let calls = Cell::new(0);
    let result = service.release_normal_chat_attempt_with_observer(
        *fresh,
        || clock.armed.store(true, Ordering::SeqCst),
        |_| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(calls.get(), 0, "regression must deny BEFORE publication");
    Ok(())
}
