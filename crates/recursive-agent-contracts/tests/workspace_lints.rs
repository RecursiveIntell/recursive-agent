use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn every_workspace_member_inherits_lints_exactly_once() -> TestResult {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("workspace root is unavailable")?
        .to_path_buf();
    let root_manifest = std::fs::read_to_string(workspace.join("Cargo.toml"))?;
    let mut checked = 0_usize;
    for entry in std::fs::read_dir(workspace.join("crates"))? {
        let path = entry?.path().join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(&workspace)?
            .parent()
            .ok_or("member parent is unavailable")?
            .to_string_lossy();
        if !root_manifest.contains(&format!("\"{relative}\"")) {
            continue;
        }
        let manifest = std::fs::read_to_string(&path)?;
        assert_eq!(
            manifest.matches("[lints]").count(),
            1,
            "{} must contain exactly one [lints] table",
            path.display()
        );
        let lint_tail = manifest
            .split_once("[lints]")
            .map(|(_, tail)| tail)
            .ok_or("lint table is missing")?;
        assert!(
            lint_tail
                .lines()
                .take_while(|line| !line.starts_with('['))
                .any(|line| line.trim() == "workspace = true"),
            "{} must inherit workspace lints",
            path.display()
        );
        checked += 1;
    }
    assert_eq!(checked, 13, "workspace member audit count changed");
    Ok(())
}
