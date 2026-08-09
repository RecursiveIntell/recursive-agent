#![cfg(feature = "later-phase-prototype")]

//! Skill registry — file-based skill manifest loading and template expansion.
//! Skills are JSON files under a registry directory. Each skill defines
//! parameterized steps that can be expanded into a RunSpecV1.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use thiserror::Error;

const MAX_SKILL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum SkillError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("skill not found: {0}")]
    NotFound(String),
    #[error("missing required param: {0}")]
    MissingParam(String),
    #[error("unknown param: {0}")]
    UnknownParam(String),
    #[error("invalid skill id")]
    InvalidId,
    #[error("skill descriptor was replaced while active")]
    Replaced,
    #[error("skill manifest exceeds the bounded read limit")]
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SkillId(String);

impl SkillId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, SkillError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || matches!(value.as_str(), "." | "..")
            || !value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        {
            return Err(SkillError::InvalidId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub params: Vec<SkillParam>,
    pub steps: Vec<SkillStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillParam {
    pub name: String,
    #[serde(default = "default_param_type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
}

fn default_param_type() -> String {
    "string".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillStep {
    pub name: String,
    pub tool: String,
    pub args: serde_json::Value,
}

pub struct SkillRegistry {
    root: File,
    identities: std::collections::BTreeMap<SkillId, (u64, u64, u64)>,
}

impl SkillRegistry {
    pub fn new(root: &Path) -> Result<Self, SkillError> {
        let root = open_directory_tree(root)?;
        let identities = enumerate_identities(&root)?;
        Ok(Self { root, identities })
    }

    pub fn load(&self, id: &SkillId) -> Result<SkillManifest, SkillError> {
        let name = format!("{}.json", id.as_str());
        let mut file = open_manifest_at(&self.root, &name)?;
        let identity = descriptor_identity(&file)?;
        if self.identities.get(id) != Some(&identity) {
            return Err(SkillError::Replaced);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_SKILL_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SKILL_BYTES {
            return Err(SkillError::TooLarge);
        }
        let current = open_manifest_at(&self.root, &name)?;
        if descriptor_identity(&current)? != identity {
            return Err(SkillError::Replaced);
        }
        let manifest: SkillManifest = serde_json::from_slice(&bytes)?;
        if manifest.name != id.as_str() {
            return Err(SkillError::InvalidId);
        }
        Ok(manifest)
    }

    pub fn list(&self) -> Result<Vec<SkillId>, SkillError> {
        Ok(self.identities.keys().cloned().collect())
    }

    /// Expand a skill call into a list of tool call specs by binding parameters.
    pub fn expand(
        &self,
        skill_id: &SkillId,
        bindings: &HashMap<String, serde_json::Value>,
    ) -> Result<Vec<SkillStep>, SkillError> {
        let manifest = self.load(skill_id)?;

        // Validate params.
        for param in &manifest.params {
            if param.required && !bindings.contains_key(&param.name) {
                return Err(SkillError::MissingParam(param.name.clone()));
            }
        }
        for key in bindings.keys() {
            if !manifest.params.iter().any(|p| &p.name == key) {
                return Err(SkillError::UnknownParam(key.clone()));
            }
        }

        // Substitute {param} placeholders in args.
        manifest
            .steps
            .iter()
            .map(|step| -> Result<SkillStep, SkillError> {
                let args_str = serde_json::to_string(&step.args)?;
                let mut substituted = args_str;
                for (key, val) in bindings {
                    let placeholder = format!("{{{key}}}");
                    let val_str = match val {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    substituted = substituted.replace(&placeholder, &val_str);
                }
                let args: serde_json::Value = serde_json::from_str(&substituted)?;
                Ok(SkillStep {
                    name: step.name.clone(),
                    tool: step.tool.clone(),
                    args,
                })
            })
            .collect()
    }
}

fn open_directory_tree(path: &Path) -> Result<File, SkillError> {
    if path.as_os_str().is_empty() || path == Path::new("/") {
        return Err(SkillError::InvalidId);
    }
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory = File::from(
        rustix::fs::open(
            start,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name.to_str().ok_or(SkillError::InvalidId)?,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(SkillError::InvalidId);
            }
        };
        directory = File::from(
            rustix::fs::openat2(
                directory.as_fd(),
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(std::io::Error::from)?,
        );
    }
    Ok(directory)
}

fn open_manifest_at(root: &File, name: &str) -> Result<File, SkillError> {
    let fd = rustix::fs::openat2(
        root.as_fd(),
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        let io = std::io::Error::from(error);
        if io.kind() == std::io::ErrorKind::NotFound {
            SkillError::NotFound(name.into())
        } else {
            SkillError::Io(io)
        }
    })?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(SkillError::InvalidId);
    }
    Ok(file)
}

fn enumerate_identities(
    root: &File,
) -> Result<std::collections::BTreeMap<SkillId, (u64, u64, u64)>, SkillError> {
    let mut identities = std::collections::BTreeMap::new();
    let pinned = format!("/proc/self/fd/{}", root.as_raw_fd());
    for entry in std::fs::read_dir(pinned)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            if let Some(stem) = path.file_stem().and_then(std::ffi::OsStr::to_str) {
                if let Ok(id) = SkillId::try_new(stem) {
                    let file = open_manifest_at(root, &format!("{}.json", id.as_str()))?;
                    identities.insert(id, descriptor_identity(&file)?);
                }
            }
        }
    }
    Ok(identities)
}

#[cfg(unix)]
fn descriptor_identity(file: &File) -> Result<(u64, u64, u64), SkillError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino(), metadata.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn load_skill_from_file() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let skill = serde_json::json!({
            "name": "greet",
            "description": "Greet someone",
            "params": [{"name": "name", "required": true}],
            "steps": [
                {"name": "say_hi", "tool": "echo", "args": {"text": "Hello {name}!"}}
            ]
        });
        std::fs::write(
            tmp.path().join("greet.json"),
            serde_json::to_string_pretty(&skill)?,
        )?;

        let reg = SkillRegistry::new(tmp.path())?;
        let manifest = reg.load(&SkillId::try_new("greet")?)?;
        assert_eq!(manifest.name, "greet");
        assert_eq!(manifest.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn expand_substitutes_params() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let skill = serde_json::json!({
            "name": "greet",
            "description": "Greet",
            "params": [{"name": "name", "required": true}],
            "steps": [
                {"name": "s1", "tool": "echo", "args": {"text": "Hello {name}!"}}
            ]
        });
        std::fs::write(
            tmp.path().join("greet.json"),
            serde_json::to_string_pretty(&skill)?,
        )?;

        let reg = SkillRegistry::new(tmp.path())?;
        let mut bindings = HashMap::new();
        bindings.insert("name".into(), serde_json::Value::String("World".into()));
        let steps = reg.expand(&SkillId::try_new("greet")?, &bindings)?;
        assert_eq!(steps[0].args["text"], "Hello World!");
        Ok(())
    }

    #[test]
    fn missing_required_param_fails() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let skill = serde_json::json!({
            "name": "greet",
            "description": "Greet",
            "params": [{"name": "name", "required": true}],
            "steps": []
        });
        std::fs::write(
            tmp.path().join("greet.json"),
            serde_json::to_string_pretty(&skill)?,
        )?;

        let reg = SkillRegistry::new(tmp.path())?;
        let bindings = HashMap::new();
        let Err(err) = reg.expand(&SkillId::try_new("greet")?, &bindings) else {
            return Err("missing required parameter unexpectedly expanded".into());
        };
        assert!(matches!(err, SkillError::MissingParam(_)));
        Ok(())
    }

    #[test]
    fn traversal_absolute_and_symlink_ids_are_rejected() -> TestResult {
        for id in ["", ".", "..", "../escape", "a/b", "/absolute"] {
            assert!(SkillId::try_new(id).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let root = tempfile::tempdir()?;
            let outside = tempfile::NamedTempFile::new()?;
            symlink(outside.path(), root.path().join("linked.json"))?;
            assert!(SkillRegistry::new(root.path()).is_err());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn active_manifest_replacement_never_returns_attacker_bytes() -> TestResult {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let root = tempfile::tempdir()?;
        let active = root.path().join("stable.json");
        let parked = root.path().join("stable.parked");
        let safe = serde_json::json!({
            "name": "stable",
            "description": "safe",
            "steps": [],
            "padding": "s".repeat(512 * 1024)
        });
        let attacker = serde_json::json!({
            "name": "stable",
            "description": "attacker",
            "steps": []
        });
        std::fs::write(&active, serde_json::to_vec(&safe)?)?;
        let registry = SkillRegistry::new(root.path())?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let active_thread = active.clone();
        let parked_thread = parked.clone();
        let attacker_bytes = serde_json::to_vec(&attacker)?;
        let replacer = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                if std::fs::rename(&active_thread, &parked_thread).is_ok() {
                    let _ = std::fs::write(&active_thread, &attacker_bytes);
                    let _ = std::fs::remove_file(&active_thread);
                    let _ = std::fs::rename(&parked_thread, &active_thread);
                }
            }
        });
        for _ in 0..32 {
            match registry.load(&SkillId::try_new("stable")?) {
                Ok(manifest) => assert_eq!(manifest.description, "safe"),
                Err(SkillError::Replaced)
                | Err(SkillError::NotFound(_))
                | Err(SkillError::Json(_))
                | Err(SkillError::Io(_)) => {}
                Err(other) => return Err(format!("unexpected replacement error: {other}").into()),
            }
        }
        stop.store(true, Ordering::Relaxed);
        replacer.join().map_err(|_| "replacement thread panicked")?;
        Ok(())
    }
}
