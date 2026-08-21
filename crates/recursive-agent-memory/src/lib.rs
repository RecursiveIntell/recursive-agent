//! Persistent memory store — SQLite-backed key-value with BM25 search.
//! Used by the `memory_put`, `memory_get`, and `memory_search` tools.

use recursive_agent_contracts::{content_digest, CurrentReceiptId};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use stack_ids::EpisodeId;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("contract: {0}")]
    Contract(#[from] recursive_agent_contracts::ContractError),
    #[error("identity: {0}")]
    Identity(String),
    #[error("memory material exceeds the admitted boundary")]
    MaterialTooLarge,
    #[error("memory row is corrupt: {0}")]
    Corruption(String),
}

const MEMORY_ID_DOMAIN: &str = "recursive-agent/memory/v1";
const MAX_NAMESPACE_BYTES: usize = 256;
const MAX_KEY_BYTES: usize = 1024;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProvenanceV1 {
    pub source: String,
    pub source_receipt: Option<CurrentReceiptId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CurrentMemoryId(EpisodeId);

impl CurrentMemoryId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        let prefix = format!("v1:{MEMORY_ID_DOMAIN}:det:");
        let suffix = value
            .strip_prefix(&prefix)
            .ok_or_else(|| MemoryError::Identity("wrong current memory id family".into()))?;
        if suffix.len() != 64
            || !suffix
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        {
            return Err(MemoryError::Identity(
                "current memory id must end in 64 lowercase hexadecimal characters".into(),
            ));
        }
        EpisodeId::try_new(value)
            .map(Self)
            .map_err(|error| MemoryError::Identity(error.to_string()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for CurrentMemoryId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for CurrentMemoryId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CurrentMemoryId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

impl Default for MemoryProvenanceV1 {
    fn default() -> Self {
        Self {
            source: "recursive-agent-memory/local/v1".into(),
            source_receipt: None,
        }
    }
}

#[derive(Serialize)]
struct MemoryIdentityMaterial<'a> {
    namespace: &'a str,
    key: &'a str,
    content: &'a str,
    provenance: &'a MemoryProvenanceV1,
}

pub fn derive_memory_id(
    namespace: &str,
    key: &str,
    content: &str,
    provenance: &MemoryProvenanceV1,
) -> Result<CurrentMemoryId, MemoryError> {
    validate_material(namespace, key, content, provenance)?;
    let digest = content_digest(&MemoryIdentityMaterial {
        namespace,
        key,
        content,
        provenance,
    })?;
    let owner = EpisodeId::deterministic(MEMORY_ID_DOMAIN, digest.hex())
        .map_err(|error| MemoryError::Identity(error.to_string()))?;
    CurrentMemoryId::try_new(owner.to_string())
}

fn validate_material(
    namespace: &str,
    key: &str,
    content: &str,
    provenance: &MemoryProvenanceV1,
) -> Result<(), MemoryError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || content.len() > MAX_CONTENT_BYTES
        || provenance.source.is_empty()
        || provenance.source.len() > MAX_KEY_BYTES
        || namespace.chars().any(char::is_control)
        || key.chars().any(char::is_control)
        || provenance.source.chars().any(char::is_control)
    {
        return Err(MemoryError::MaterialTooLarge);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: CurrentMemoryId,
    pub namespace: String,
    pub key: String,
    pub content: String,
    pub provenance: MemoryProvenanceV1,
    pub recorded_at: String,
}

pub struct MemoryStore {
    db: Connection,
}

impl MemoryStore {
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                content TEXT NOT NULL,
                provenance TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_memories_ns ON memories(namespace);
            CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(namespace, key);",
        )?;
        Ok(Self { db })
    }

    pub fn put(
        &self,
        namespace: &str,
        key: &str,
        content: &str,
    ) -> Result<CurrentMemoryId, MemoryError> {
        self.put_with_provenance(namespace, key, content, &MemoryProvenanceV1::default())
    }

    pub fn put_with_provenance(
        &self,
        namespace: &str,
        key: &str,
        content: &str,
        provenance: &MemoryProvenanceV1,
    ) -> Result<CurrentMemoryId, MemoryError> {
        let id = derive_memory_id(namespace, key, content, provenance)?;
        let provenance_bytes = recursive_agent_contracts::jcs_canonical(provenance)?;
        let provenance_json = String::from_utf8(provenance_bytes)
            .map_err(|error| MemoryError::Corruption(error.to_string()))?;
        self.db.execute(
            "INSERT OR IGNORE INTO memories (id, namespace, key, content, provenance) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.as_str(), namespace, key, content, provenance_json],
        )?;
        Ok(id)
    }

    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<MemoryEntry>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, namespace, key, content, provenance, recorded_at FROM memories WHERE namespace = ?1 AND key = ?2 ORDER BY recorded_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace, key])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(decode_row(row)?))
    }

    pub fn search(
        &self,
        namespace: &str,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        // BM25-inspired: tokenize query, score by term frequency in content.
        let tokens: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();

        let mut stmt = self.db.prepare(
            "SELECT id, namespace, key, content, provenance, recorded_at FROM memories WHERE namespace = ?1",
        )?;
        let mut query_rows = stmt.query(params![namespace])?;
        let mut rows = Vec::new();
        while let Some(row) = query_rows.next()? {
            rows.push(decode_row(row)?);
        }

        // Score each entry.
        let mut scored: Vec<(f64, MemoryEntry)> = rows
            .into_iter()
            .map(|entry| {
                let content_lower = entry.content.to_lowercase();
                let score: f64 = tokens
                    .iter()
                    .map(|t| content_lower.matches(t).count() as f64)
                    .sum();
                (score, entry)
            })
            .filter(|(s, _)| *s > 0.0)
            .collect();

        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        scored.truncate(top_k);

        Ok(scored.into_iter().map(|(_, e)| e).collect())
    }
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<MemoryEntry, MemoryError> {
    let field = |index| {
        row.get::<_, String>(index)
            .map_err(|error| MemoryError::Corruption(format!("field {index}: {error}")))
    };
    let raw_id = field(0)?;
    let namespace = field(1)?;
    let key = field(2)?;
    let content = field(3)?;
    let provenance_json = field(4)?;
    let recorded_at = field(5)?;
    let id = CurrentMemoryId::try_new(raw_id)
        .map_err(|error| MemoryError::Corruption(error.to_string()))?;
    let provenance: MemoryProvenanceV1 = serde_json::from_str(&provenance_json)
        .map_err(|error| MemoryError::Corruption(format!("provenance: {error}")))?;
    validate_material(&namespace, &key, &content, &provenance)
        .map_err(|error| MemoryError::Corruption(error.to_string()))?;
    let expected = derive_memory_id(&namespace, &key, &content, &provenance)
        .map_err(|error| MemoryError::Corruption(error.to_string()))?;
    if id != expected {
        return Err(MemoryError::Corruption(
            "stored identity does not match canonical material".into(),
        ));
    }
    if recorded_at.is_empty() || recorded_at.chars().any(char::is_control) {
        return Err(MemoryError::Corruption(
            "recorded_at is missing or invalid".into(),
        ));
    }
    Ok(MemoryEntry {
        id,
        namespace,
        key,
        content,
        provenance,
        recorded_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn put_and_get() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = MemoryStore::open(&tmp.path().join("test.db"))?;
        let id = store.put("test", "greeting", "hello world")?;
        assert!(id.as_str().starts_with("v1:recursive-agent/memory/v1:det:"));
        let entry = store
            .get("test", "greeting")?
            .ok_or("stored memory entry is missing")?;
        assert_eq!(entry.content, "hello world");
        Ok(())
    }

    #[test]
    fn get_missing_returns_none() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = MemoryStore::open(&tmp.path().join("test.db"))?;
        let entry = store.get("test", "nope")?;
        assert!(entry.is_none());
        Ok(())
    }

    #[test]
    fn search_finds_relevant() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = MemoryStore::open(&tmp.path().join("test.db"))?;
        store.put("ns", "k1", "Rust is a systems programming language")?;
        store.put("ns", "k2", "Python is great for data science")?;
        store.put("ns", "k3", "Rust has great memory safety")?;
        let results = store.search("ns", "rust", 5)?;
        assert_eq!(results.len(), 2);
        Ok(())
    }

    #[test]
    fn identical_material_is_idempotent_and_content_changes_identity() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let store = MemoryStore::open(&tmp.path().join("test.db"))?;
        let first = store.put("ns", "key", "content")?;
        let second = store.put("ns", "key", "content")?;
        let changed = store.put("ns", "key", "changed")?;
        assert_eq!(first, second);
        assert_ne!(first, changed);
        Ok(())
    }

    #[test]
    fn identity_is_stable_across_processes() -> TestResult {
        if std::env::var_os("RA_MEMORY_ID_PROBE").is_some() {
            let id = derive_memory_id("ns", "key", "content", &MemoryProvenanceV1::default())?;
            println!("MEMORY_ID_PROBE={id}");
            return Ok(());
        }
        let executable = std::env::current_exe()?;
        let probe = || -> Result<String, Box<dyn std::error::Error>> {
            let output = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "tests::identity_is_stable_across_processes",
                    "--nocapture",
                ])
                .env("RA_MEMORY_ID_PROBE", "1")
                .output()?;
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout)?;
            Ok(stdout
                .lines()
                .find_map(|line| line.strip_prefix("MEMORY_ID_PROBE="))
                .ok_or("memory identity probe output is missing")?
                .to_string())
        };
        assert_eq!(probe()?, probe()?);
        Ok(())
    }

    fn corrupt_store() -> Result<MemoryStore, MemoryError> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE memories (
                id,
                namespace,
                key,
                content,
                provenance,
                recorded_at
            );",
        )?;
        Ok(MemoryStore { db })
    }

    fn insert_raw(
        store: &MemoryStore,
        id: rusqlite::types::Value,
        namespace: rusqlite::types::Value,
        key: rusqlite::types::Value,
        content: rusqlite::types::Value,
        provenance: rusqlite::types::Value,
        recorded_at: rusqlite::types::Value,
    ) -> Result<(), MemoryError> {
        store.db.execute(
            "INSERT INTO memories VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, namespace, key, content, provenance, recorded_at],
        )?;
        Ok(())
    }

    fn text(value: &str) -> rusqlite::types::Value {
        rusqlite::types::Value::Text(value.into())
    }

    #[test]
    fn sqlite_tampering_is_typed_corruption_and_never_omitted() -> TestResult {
        let provenance = MemoryProvenanceV1::default();
        let valid_id = derive_memory_id("ns", "key", "content", &provenance)?.to_string();
        let provenance_json = serde_json::to_string(&provenance)?;
        for bad_id in [
            "v1:recursive-agent/run/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            let store = corrupt_store()?;
            insert_raw(
                &store,
                text(bad_id),
                text("ns"),
                text("key"),
                text("content"),
                provenance_json.clone().into(),
                text("2026-08-05T00:00:00Z"),
            )?;
            assert!(matches!(
                store.get("ns", "key"),
                Err(MemoryError::Corruption(_))
            ));
        }

        for (content, stored_provenance, recorded_at) in [
            (
                "mutated",
                provenance_json.clone(),
                rusqlite::types::Value::Text("2026-08-05T00:00:00Z".into()),
            ),
            (
                "content",
                serde_json::to_string(&MemoryProvenanceV1 {
                    source: "mutated".into(),
                    source_receipt: None,
                })?,
                rusqlite::types::Value::Text("2026-08-05T00:00:00Z".into()),
            ),
            (
                "content",
                provenance_json.clone(),
                rusqlite::types::Value::Null,
            ),
        ] {
            let store = corrupt_store()?;
            insert_raw(
                &store,
                valid_id.clone().into(),
                text("ns"),
                text("key"),
                text(content),
                stored_provenance.into(),
                recorded_at,
            )?;
            assert!(matches!(
                store.get("ns", "key"),
                Err(MemoryError::Corruption(_))
            ));
        }

        let store = corrupt_store()?;
        insert_raw(
            &store,
            valid_id.into(),
            text("ns"),
            text("key"),
            text("content"),
            provenance_json.clone().into(),
            text("2026-08-05T00:00:00Z"),
        )?;
        insert_raw(
            &store,
            rusqlite::types::Value::Null,
            text("ns"),
            text("corrupt"),
            text("content"),
            provenance_json.into(),
            text("2026-08-05T00:00:00Z"),
        )?;
        assert!(matches!(
            store.search("ns", "content", 10),
            Err(MemoryError::Corruption(_))
        ));
        Ok(())
    }
}
