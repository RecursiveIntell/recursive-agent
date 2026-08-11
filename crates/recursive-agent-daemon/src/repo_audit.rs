//! Deterministic, bounded source inventory for an explicitly configured root.
//!
//! This is an evidence collector, not an evaluator: it executes no subprocesses,
//! follows no symlinks, calls no provider or network, and returns no proposal.
//! Its TODO/FIXME signal intentionally covers ordinary `//` comments in admitted
//! non-test Rust source only; doc and block comments are outside this v1 scope.

use std::fs;
use std::path::{Path, PathBuf};

use recursive_agent_contracts::ContentDigest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_MAX_FILES: usize = 1_024;
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1_024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_MAX_MARKERS: usize = 128;
const DEFAULT_MAX_DIRECTORY_ENTRIES: u64 = 16 * 1_024;
const DEFAULT_MAX_DIRECTORY_DEPTH: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLimits {
    configured_root: Option<PathBuf>,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_markers: usize,
    max_directory_entries: u64,
    max_directory_depth: u32,
}

impl AuditLimits {
    pub fn production(configured_root: PathBuf) -> Result<Self, AuditError> {
        Ok(Self {
            configured_root: Some(canonical_dir(&configured_root)?),
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_markers: DEFAULT_MAX_MARKERS,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
            max_directory_depth: DEFAULT_MAX_DIRECTORY_DEPTH,
        })
    }

    pub fn test_defaults() -> Self {
        Self {
            configured_root: None,
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_markers: DEFAULT_MAX_MARKERS,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
            max_directory_depth: DEFAULT_MAX_DIRECTORY_DEPTH,
        }
    }

    pub fn with_configured_root(mut self, root: &Path) -> Result<Self, AuditError> {
        self.configured_root = Some(canonical_dir(root)?);
        Ok(self)
    }

    pub fn with_max_files(mut self, max_files: usize) -> Result<Self, AuditError> {
        if max_files == 0 {
            return Err(AuditError::InvalidLimits);
        }
        self.max_files = max_files;
        Ok(self)
    }

    pub fn with_max_directory_entries(
        mut self,
        max_directory_entries: u64,
    ) -> Result<Self, AuditError> {
        if max_directory_entries == 0 {
            return Err(AuditError::InvalidLimits);
        }
        self.max_directory_entries = max_directory_entries;
        Ok(self)
    }

    pub fn with_max_directory_depth(
        mut self,
        max_directory_depth: u32,
    ) -> Result<Self, AuditError> {
        if max_directory_depth == 0 {
            return Err(AuditError::InvalidLimits);
        }
        self.max_directory_depth = max_directory_depth;
        Ok(self)
    }

    pub fn audit_requested(&self, requested_root: &Path) -> Result<RepoAuditV1, AuditError> {
        audit_root(requested_root, self.clone())
    }

    pub fn configured_scope_digest(&self) -> Result<ContentDigest, AuditError> {
        let root = self
            .configured_root
            .as_ref()
            .ok_or(AuditError::InvalidRoot)?;
        let mut material = b"recursive-agent:repo-audit-scope:v1\0".to_vec();
        material.extend_from_slice(root.to_string_lossy().as_bytes());
        Ok(ContentDigest::compute(&material))
    }

    pub fn audit(&self) -> Result<RepoAuditV1, AuditError> {
        let root = self
            .configured_root
            .as_ref()
            .ok_or(AuditError::InvalidRoot)?;
        audit_root(root, self.clone())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit root is not an accessible directory")]
    InvalidRoot,
    #[error("audit root differs from the configured canonical boundary")]
    RootMismatch,
    #[error("audit limits are invalid")]
    InvalidLimits,
    #[error("regular-file count exceeds the admitted audit limit")]
    FileLimitExceeded,
    #[error("regular-file size exceeds the admitted audit limit")]
    FileSizeLimitExceeded,
    #[error("aggregate source bytes exceed the admitted audit limit")]
    TotalSizeLimitExceeded,
    #[error("directory traversal exceeds an admitted safety limit")]
    TraversalLimitExceeded,
    #[error("audit filesystem access failed")]
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TodoMarkerV1 {
    pub path: String,
    pub line: u64,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicMacroV1 {
    pub path: String,
    pub line: u64,
    pub macro_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalCandidateV1 {
    pub path: String,
    pub line: u64,
    pub marker: String,
    pub advisory_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoAuditV1 {
    pub schema: String,
    pub marker_scope: String,
    pub files_scanned: u64,
    pub source_bytes_scanned: u64,
    pub skipped_symlinks: u64,
    pub todo_markers: Vec<TodoMarkerV1>,
    pub panic_macros: Vec<PanicMacroV1>,
    pub proposal_candidates: Vec<ProposalCandidateV1>,
}

pub fn audit_root(root: &Path, limits: AuditLimits) -> Result<RepoAuditV1, AuditError> {
    let root = canonical_dir(root)?;
    if limits
        .configured_root
        .as_ref()
        .is_some_and(|configured| configured != &root)
    {
        return Err(AuditError::RootMismatch);
    }

    let mut regular_files = Vec::new();
    let mut skipped_symlinks = 0_u64;
    let mut traversed_entries = 0_u64;
    collect_regular_files(
        &root,
        &root,
        &mut regular_files,
        &mut skipped_symlinks,
        &mut traversed_entries,
        0,
        &limits,
    )?;
    regular_files.sort();
    if regular_files.len() > limits.max_files {
        return Err(AuditError::FileLimitExceeded);
    }

    let mut bytes_scanned = 0_u64;
    let mut markers = Vec::new();
    let mut panic_macros = Vec::new();
    for path in &regular_files {
        let metadata = fs::metadata(path).map_err(|_| AuditError::Io)?;
        let size = metadata.len();
        if size > limits.max_file_bytes {
            return Err(AuditError::FileSizeLimitExceeded);
        }
        bytes_scanned = bytes_scanned
            .checked_add(size)
            .ok_or(AuditError::TotalSizeLimitExceeded)?;
        if bytes_scanned > limits.max_total_bytes {
            return Err(AuditError::TotalSizeLimitExceeded);
        }
        let content = fs::read_to_string(path).map_err(|_| AuditError::Io)?;
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| AuditError::Io)?
            .to_string_lossy()
            .replace('\\', "/");
        if is_actionable_rust_path(&relative) {
            for (index, line) in content.lines().enumerate() {
                let marker = rust_line_comment(line).and_then(actionable_marker);
                if let Some(marker) = marker {
                    if markers.len() + panic_macros.len() == limits.max_markers {
                        break;
                    }
                    markers.push(TodoMarkerV1 {
                        path: relative.clone(),
                        line: u64::try_from(index + 1).map_err(|_| AuditError::Io)?,
                        marker: marker.into(),
                    });
                }
            }
            for (line, macro_name) in executable_panic_macros(&content) {
                if markers.len() + panic_macros.len() == limits.max_markers {
                    break;
                }
                panic_macros.push(PanicMacroV1 {
                    path: relative.clone(),
                    line,
                    macro_name: macro_name.into(),
                });
            }
        }
    }
    let mut proposal_candidates: Vec<_> = markers
        .iter()
        .map(|marker| ProposalCandidateV1 {
            path: marker.path.clone(),
            line: marker.line,
            marker: marker.marker.clone(),
            advisory_action:
                "Review and resolve the source marker; no source change is authorized by this audit."
                    .into(),
        })
        .collect();
    proposal_candidates.extend(panic_macros.iter().map(|macro_finding| ProposalCandidateV1 {
        path: macro_finding.path.clone(),
        line: macro_finding.line,
        marker: macro_finding.macro_name.clone(),
        advisory_action:
            "Review and resolve the executable panic macro; no source change is authorized by this audit."
                .into(),
    }));
    Ok(RepoAuditV1 {
        schema: "recursive-agent.repo-audit/v4".into(),
        marker_scope: "ordinary-rust-line-comments-v1; executable-panic-macros-v1".into(),
        files_scanned: u64::try_from(regular_files.len()).map_err(|_| AuditError::Io)?,
        source_bytes_scanned: bytes_scanned,
        skipped_symlinks,
        todo_markers: markers,
        panic_macros,
        proposal_candidates,
    })
}

fn is_actionable_rust_path(relative: &str) -> bool {
    relative.ends_with(".rs")
        && !relative
            .split('/')
            .any(|component| matches!(component, "tests" | "fixtures" | "test-fixtures"))
}

fn actionable_marker(comment: &str) -> Option<&'static str> {
    for marker in ["TODO", "FIXME"] {
        let Some(rest) = comment.trim_start().strip_prefix(marker) else {
            continue;
        };
        let message = rest.strip_prefix(':').unwrap_or(rest).trim();
        if !message.is_empty() {
            return Some(marker);
        }
    }
    None
}

fn executable_panic_macros(content: &str) -> Vec<(u64, &'static str)> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment(u32),
        Quoted(u8),
        Raw(usize),
    }

    let bytes = content.as_bytes();
    let mut findings = Vec::new();
    let mut index = 0;
    let mut line = 1_u64;
    let mut state = State::Code;
    while index < bytes.len() {
        match state {
            State::Code => {
                if bytes[index..].starts_with(b"//") {
                    state = State::LineComment;
                    index += 2;
                } else if bytes[index..].starts_with(b"/*") {
                    state = State::BlockComment(1);
                    index += 2;
                } else if let Some(hashes) = raw_string_hashes(bytes, index) {
                    state = State::Raw(hashes);
                    index += 2 + hashes;
                } else if matches!(bytes[index], b'\"' | b'\'') {
                    state = State::Quoted(bytes[index]);
                    index += 1;
                } else if let Some(macro_name) = panic_macro_at(bytes, index) {
                    findings.push((line, macro_name));
                    index += macro_name.len();
                } else {
                    if bytes[index] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    index += 1;
                }
            }
            State::LineComment => {
                if bytes[index] == b'\n' {
                    line = line.saturating_add(1);
                    state = State::Code;
                }
                index += 1;
            }
            State::BlockComment(depth) => {
                if bytes[index..].starts_with(b"/*") {
                    state = State::BlockComment(depth.saturating_add(1));
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    state = if depth == 1 {
                        State::Code
                    } else {
                        State::BlockComment(depth - 1)
                    };
                    index += 2;
                } else {
                    if bytes[index] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    index += 1;
                }
            }
            State::Quoted(quote) => {
                if bytes[index] == b'\\' {
                    index = index.saturating_add(2);
                } else {
                    if bytes[index] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    if bytes[index] == quote {
                        state = State::Code;
                    }
                    index += 1;
                }
            }
            State::Raw(hashes) => {
                if bytes[index] == b'\n' {
                    line = line.saturating_add(1);
                }
                if bytes[index] == b'\"'
                    && (0..hashes).all(|offset| bytes.get(index + 1 + offset) == Some(&b'#'))
                {
                    index += 1 + hashes;
                    state = State::Code;
                } else {
                    index += 1;
                }
            }
        }
    }
    findings
}

fn raw_string_hashes(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    let mut hashes = 0;
    while bytes.get(index + 1 + hashes) == Some(&b'#') {
        hashes += 1;
    }
    (bytes.get(index + 1 + hashes) == Some(&b'\"')).then_some(hashes)
}

fn panic_macro_at(bytes: &[u8], index: usize) -> Option<&'static str> {
    for macro_name in ["todo!", "unimplemented!"] {
        let name = macro_name.as_bytes();
        let before_is_ident = index
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
        let after_is_ident = bytes
            .get(index + name.len())
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
        if !before_is_ident && !after_is_ident && bytes[index..].starts_with(name) {
            return Some(macro_name);
        }
    }
    None
}

fn rust_line_comment(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            return line.get(index + 2..);
        }
        if bytes[index] == b'\"' {
            index = skip_quoted(bytes, index + 1, b'\"');
        } else if bytes[index] == b'\'' {
            index = skip_quoted(bytes, index + 1, b'\'');
        } else if bytes[index] == b'r' {
            let mut hashes = 0;
            while bytes.get(index + 1 + hashes) == Some(&b'#') {
                hashes += 1;
            }
            if bytes.get(index + 1 + hashes) == Some(&b'\"') {
                let mut close = b"\"".to_vec();
                close.extend(std::iter::repeat(b'#').take(hashes));
                index = index + 2 + hashes;
                while index < bytes.len() && !bytes[index..].starts_with(&close) {
                    index += 1;
                }
                index = index.saturating_add(close.len());
            } else {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    None
}

fn skip_quoted(bytes: &[u8], mut index: usize, quote: u8) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = index.saturating_add(2);
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    index
}

fn canonical_dir(path: &Path) -> Result<PathBuf, AuditError> {
    let root = fs::canonicalize(path).map_err(|_| AuditError::InvalidRoot)?;
    if !root.is_dir() {
        return Err(AuditError::InvalidRoot);
    }
    Ok(root)
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
    skipped_symlinks: &mut u64,
    traversed_entries: &mut u64,
    depth: u32,
    limits: &AuditLimits,
) -> Result<(), AuditError> {
    for entry in fs::read_dir(current).map_err(|_| AuditError::Io)? {
        *traversed_entries = traversed_entries
            .checked_add(1)
            .ok_or(AuditError::TraversalLimitExceeded)?;
        if *traversed_entries > limits.max_directory_entries {
            return Err(AuditError::TraversalLimitExceeded);
        }
        let entry = entry.map_err(|_| AuditError::Io)?;
        let file_type = entry.file_type().map_err(|_| AuditError::Io)?;
        let path = entry.path();
        if file_type.is_symlink() {
            *skipped_symlinks = skipped_symlinks.saturating_add(1);
        } else if file_type.is_dir() {
            let name = entry.file_name();
            if !matches!(
                name.to_str(),
                Some(".git" | "target" | ".hermes" | "node_modules")
            ) {
                if depth >= limits.max_directory_depth {
                    return Err(AuditError::TraversalLimitExceeded);
                }
                collect_regular_files(
                    root,
                    &path,
                    files,
                    skipped_symlinks,
                    traversed_entries,
                    depth + 1,
                    limits,
                )?;
            }
        } else if file_type.is_file() && is_admitted_source_file(&path, root) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_admitted_source_file(path: &Path, _root: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("rs" | "toml" | "md")
    )
}
