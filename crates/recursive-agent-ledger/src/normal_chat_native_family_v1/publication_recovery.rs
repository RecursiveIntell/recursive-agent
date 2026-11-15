//! Private crash-prefix input. Never a terminal proof or caller-authored authority.
use super::degradation_preparation::{
    prepare_verified_family, NormalChatSessionDegradationPreparationErrorV1 as E,
    PreparedNormalChatSessionDegradationV1,
};
use super::*;
use crate::NormalChatSessionGateV1;

pub(super) struct RecoveryCandidateV1 {
    raw: Vec<u8>,
    metadata: Vec<u8>,
    rows: Vec<ReceiptV1>,
    prefix: VerifiedReceiptSnapshot,
    inventory: Vec<ArtifactDescriptorV1>,
    end: usize,
    tail: Vec<u8>,
    created_at: DateTime<Utc>,
}
impl RecoveryCandidateV1 {
    fn read(root: &File, id: &CurrentRunId) -> Result<Self, LedgerError> {
        with_exclusive_lock(root, |root| {
            let raw = read_bounded_regular_at(root, "receipts.ndjson", MAX_RECEIPT_LOG_BYTES)?;
            let mut complete = raw.clone();
            let mut tail = Vec::new();
            if !complete.is_empty() && complete.last() != Some(&b'\n') {
                let start = complete
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |i| i + 1);
                match serde_json::from_slice::<ReceiptV1>(&complete[start..]) {
                    Ok(row) if row.canonical_bytes()? == complete[start..] => complete.push(b'\n'),
                    Err(e) if e.is_eof() => {
                        tail = complete.split_off(start);
                    }
                    _ => return Err(LedgerError::AmbiguousTrailingRecord),
                }
            }
            let scan = scan_complete_bytes(&complete)?;
            let end = scan
                .receipts
                .iter()
                .position(|r| r.kind == ReceiptKindV1::PermitRevoked)
                .unwrap_or(scan.receipts.len());
            if end < 6 || (end - 3) % 3 != 0 || scan.receipts.len() - end > 3 {
                return Err(invalid("recovery parent cardinality differs"));
            }
            let mut prefix_bytes = Vec::new();
            for row in &scan.receipts[..end] {
                prefix_bytes.extend(row.canonical_bytes()?);
                prefix_bytes.push(b'\n');
            }
            let prefix_scan = scan_complete_bytes(&prefix_bytes)?;
            let (lifecycle, verified_artifacts) = validate_authoritative_sequence(
                root,
                &prefix_scan.receipts,
                LifecycleValidationMode::AppendInProgress,
            )?;
            if lifecycle.run_id.as_ref() != Some(id) {
                return Err(invalid("recovery parent id differs"));
            }
            let metadata = read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)?;
            let meta: ChainMeta = serde_json::from_slice(&metadata)?;
            if jcs_canonical(&meta)? != metadata
                || meta.length < end as u64
                || meta.length > scan.length
                || scan.length - meta.length > 1
            {
                return Err(invalid("recovery metadata is not a publisher crash prefix"));
            }
            let mut meta_bytes = Vec::new();
            for row in scan.receipts.iter().take(meta.length as usize) {
                meta_bytes.extend(row.canonical_bytes()?);
                meta_bytes.push(b'\n');
            }
            if metadata_for(&scan_complete_bytes(&meta_bytes)?, meta.created_at) != meta {
                return Err(invalid("recovery metadata head differs"));
            }
            let store = ArtifactStore::from_run_root_fd(root, false)?;
            let mut inventory = Vec::new();
            let mut count = 0usize;
            for entry in
                rustix::fs::Dir::read_from(store.dir.as_fd()).map_err(std::io::Error::from)?
            {
                let entry = entry.map_err(std::io::Error::from)?;
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    continue;
                }
                count += 1;
                if count > 4096 {
                    return Err(invalid("recovery inventory bound exceeded"));
                }
                let name = std::str::from_utf8(name)
                    .map_err(|_| invalid("invalid recovery artifact name"))?;
                if name.ends_with(".meta") {
                    let bytes = read_bounded_regular_at(&store.dir, name, MAX_ARTIFACT_META_BYTES)?;
                    let descriptor: ArtifactDescriptorV1 = serde_json::from_slice(&bytes)?;
                    if jcs_canonical(&descriptor)? != bytes {
                        return Err(invalid("noncanonical recovery artifact descriptor"));
                    }
                    inventory.push(descriptor);
                }
            }
            store.require_exact_inventory(&inventory)?;
            let prefix = VerifiedReceiptSnapshot {
                verification: ChainVerification {
                    ok: true,
                    current_strict_success: false,
                    length: prefix_scan.length,
                    final_head: prefix_scan.head.to_string(),
                    verified_artifacts,
                    terminal_state: lifecycle
                        .terminal_state
                        .unwrap_or(RunTerminalStateV1::LegacyUnknown),
                    verified_run_id: lifecycle.run_id,
                    first_divergence: None,
                },
                receipts: Arc::from(prefix_scan.receipts),
            };
            Ok(Self {
                raw,
                metadata,
                rows: scan.receipts,
                prefix,
                inventory,
                end,
                tail,
                created_at: meta.created_at,
            })
        })
    }
    pub(super) fn require_unchanged_locked(&self, root: &File) -> Result<(), LedgerError> {
        if read_bounded_regular_at(root, "receipts.ndjson", MAX_RECEIPT_LOG_BYTES)? != self.raw
            || read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)? != self.metadata
        {
            return Err(invalid("recovery captured bytes changed"));
        }
        Ok(())
    }
    pub(super) fn prefix_snapshot(
        &self,
        root: &File,
    ) -> Result<VerifiedReceiptSnapshot, LedgerError> {
        with_exclusive_lock(root, |root| self.require_unchanged_locked(root))?;
        Ok(self.prefix.clone())
    }
    pub(super) fn inventory(&self) -> Vec<ArtifactDescriptorV1> {
        self.inventory.clone()
    }
}
fn candidate<'a>(
    plan: &'a PreparedNormalChatSessionDegradationV1<'_>,
) -> Result<&'a RecoveryCandidateV1, LedgerError> {
    match &plan.family.parent_read {
        ParentReadV1::Recovery(c) => Ok(c),
        _ => Err(invalid("missing recovery candidate")),
    }
}
fn drafts(plan: &PreparedNormalChatSessionDegradationV1<'_>) -> Vec<ReceiptDraftV1> {
    let root = plan.root_revocation_draft();
    let mut marker = root.clone();
    marker.kind = ReceiptKindV1::NormalChatSessionDegradedV1;
    marker.valid_time = plan.marker().finalized_at;
    marker.outcome = plan.outcome().clone();
    marker.artifact_refs = vec![plan.marker_descriptor().clone()];
    let mut terminal = marker.clone();
    terminal.kind = ReceiptKindV1::RunFinalized;
    terminal.artifact_refs.clear();
    vec![root, marker, terminal]
}
fn prove(plan: &PreparedNormalChatSessionDegradationV1<'_>) -> Result<(), E> {
    let c = candidate(plan)?;
    let expected = drafts(plan);
    for (row, draft) in c.rows[c.end..].iter().zip(&expected) {
        super::terminal_verification::compare(draft.clone(), row)?;
        for descriptor in &row.artifact_refs {
            plan.family.parent_store.verify_descriptor(descriptor)?;
        }
    }
    let mut allowed = plan.family.inventory.clone();
    allowed.extend([
        plan.root_revocation_descriptor().clone(),
        plan.marker_descriptor().clone(),
    ]);
    plan.family
        .parent_store
        .require_inventory_subset(&allowed)?;
    let root_present = c.inventory.contains(plan.root_revocation_descriptor());
    let marker_present = c.inventory.contains(plan.marker_descriptor());
    if marker_present && !root_present || c.rows.len() > c.end && !marker_present {
        return Err(E::Invalid("artifact inventory is not a publisher prefix"));
    }
    if !c.tail.is_empty() {
        let draft = expected
            .get(c.rows.len() - c.end)
            .ok_or(E::Invalid("tail after terminal"))?;
        let head = c.rows.last().ok_or(E::Invalid("empty recovery rows"))?;
        let head = chain_digest_from_raw(&head.prev_chain_digest, &head.canonical_bytes()?)?;
        let template = make_receipt(draft.clone(), head)?.canonical_bytes()?;
        // Refuse ambiguous time-bearing torn rows. Canonical prefixes before
        // recorded_time are deterministic and can be proven against source.
        let time = b"\"recorded_time\":";
        let bound = template
            .windows(time.len())
            .position(|w| w == time)
            .ok_or(E::Invalid("recorded time field absent"))?
            + time.len();
        if c.tail.len() > bound || !template.starts_with(&c.tail) {
            return Err(E::Invalid("torn suffix differs from native projection"));
        }
    }
    Ok(())
}
/// Explicit cold-history recovery under the matching existing caller-held gate.
/// Only source-derived missing publication rows are written. No send/native
/// authority transition, grant, lease renewal or fabricated provider outcome.
pub fn recover_normal_chat_session_degradation_from_runtime_root_fd<'g>(
    output: &File,
    id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
) -> Result<VerifiedNormalChatDegradedSessionV1<'g>, E> {
    recover_normal_chat_session_degradation_from_runtime_root_fd_with_observer(
        output,
        id,
        gate,
        || {},
    )
}
#[doc(hidden)]
pub fn recover_normal_chat_session_degradation_from_runtime_root_fd_with_observer<'g>(
    output: &File,
    id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
    before_append: impl FnOnce(),
) -> Result<VerifiedNormalChatDegradedSessionV1<'g>, E> {
    recover_normal_chat_session_degradation_from_runtime_root_fd_with_observers(
        output,
        id,
        gate,
        before_append,
        || {},
    )
}
#[doc(hidden)]
pub fn recover_normal_chat_session_degradation_from_runtime_root_fd_with_observers<'g>(
    output: &File,
    id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
    before_append: impl FnOnce(),
    before_return: impl FnOnce(),
) -> Result<VerifiedNormalChatDegradedSessionV1<'g>, E> {
    let output = output.try_clone()?;
    let identity = run_root_identity(&output)?;
    let parent = RunPin::open(&output, id)?;
    gate.check(&parent.root)?;
    let input = RecoveryCandidateV1::read(&parent.root, id)?;
    if input.rows.len() == input.end + 3
        && input.raw.last() == Some(&b'\n')
        && input.metadata
            == jcs_canonical(&metadata_for(
                &scan_complete_bytes(&input.raw)?,
                input.created_at,
            ))?
    {
        // Already complete history still needs a noncreating durability ACK:
        // the prior writer may have lost its final log/directory fsync ACK.
        // First prove the complete current native/source join, then sync only
        // the exact captured bytes, and recheck after the final observer.
        before_append();
        let proof = verify_degraded_normal_chat_session_from_runtime_root_fd(&output, id, gate)?;
        with_exclusive_lock(&parent.root, |root| {
            gate.check(root).map_err(|e| invalid(&e.to_string()))?;
            input.require_unchanged_locked(root)?;
            parent.check(&output)?;
            sync_retained_receipt_log_locked(root)
        })?;
        before_return();
        proof.recheck()?;
        return Ok(proof);
    }
    let family = verify_family_from_pins(
        output,
        identity,
        parent,
        id,
        ParentReadV1::Recovery(Box::new(input)),
        |root| gate.check(root).map_err(|e| invalid(&e.to_string())),
        || {},
    )?;
    let plan = prepare_verified_family(family, gate)?;
    prove(&plan)?;
    before_append();
    plan.recheck()?;
    prove(&plan)?;
    let c = candidate(&plan)?;
    let store = &plan.family.parent_store;
    // Existing referenced artifacts were verified above, never reconstructed.
    for (descriptor, bytes) in [
        (
            plan.root_revocation_descriptor(),
            plan.root_revocation_bytes(),
        ),
        (plan.marker_descriptor(), plan.marker_bytes()),
    ] {
        if !c.inventory.contains(descriptor)
            && store.put(bytes, "application/json", None)? != *descriptor
        {
            return Err(E::Invalid("recovery artifact differs"));
        }
    }
    let mut all = plan.family.inventory.clone();
    all.extend([
        plan.root_revocation_descriptor().clone(),
        plan.marker_descriptor().clone(),
    ]);
    store.require_exact_inventory(&all)?;
    with_exclusive_lock(&plan.family.parent.root, |root| {
        gate.check(root).map_err(|e| invalid(&e.to_string()))?;
        c.require_unchanged_locked(root)?;
        plan.family.parent.check(&plan.family.output)?;
        for pin in &plan.family.pins {
            pin.check(&plan.family.output)?;
        }
        store.require_exact_inventory(&all)?;
        store.require_locator_matches(root)?;
        // Validate the entire proposal before the canonical tail owner mutates.
        let mut normalized = Vec::new();
        for row in &c.rows {
            normalized.extend(row.canonical_bytes()?);
            normalized.push(b'\n');
        }
        let captured_scan = scan_complete_bytes(&normalized)?;
        let mut proposed = captured_scan.receipts.clone();
        let mut head = captured_scan.head.clone();
        let mut missing = Vec::new();
        for draft in drafts(&plan).into_iter().skip(c.rows.len() - c.end) {
            let row = make_receipt(draft, head)?;
            head = chain_digest_from_raw(&row.prev_chain_digest, &row.canonical_bytes()?)?;
            proposed.push(row.clone());
            missing.push(row);
        }
        validate_local_authoritative_sequence(
            root,
            &proposed,
            LifecycleValidationMode::StrictCurrent,
        )?;
        let mut scan = recover_and_scan(root)?;
        if scan.receipts != c.rows || scan.head != captured_scan.head {
            return Err(invalid("recovered complete prefix differs"));
        }
        // A complete retained append may never have reached log fsync. Confirm
        // it BEFORE publishing repaired metadata, even when no rows are missing.
        sync_retained_receipt_log_locked(root)?;
        // Preserve original created_at; no missing/malformed metadata fallback.
        let expected = metadata_for(&scan, c.created_at);
        if jcs_canonical(&expected)? != c.metadata {
            write_metadata_atomic(root, &expected, None)?;
        }
        for row in missing {
            scan = persist_validated_receipt_locked(root, scan, row, c.created_at, None)?;
        }
        Ok(())
    })?;
    verify_degraded_normal_chat_session_from_runtime_root_fd_with_observer(
        &plan.family.output,
        id,
        gate,
        before_return,
    )
}
