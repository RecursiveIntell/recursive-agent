use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use recursive_agent_contracts::RunSpecV1;
use recursive_agent_ledger::verify;
use recursive_agent_runner::{replay, run_spec};

#[derive(Parser, Debug)]
#[command(
    name = "ra",
    version,
    about = "recursive-agent M0 — provenance-native agent CLI"
)]
struct Cli {
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print runtime and capability info. No effects, no provider.
    Doctor,
    /// Run a spec and persist a receipt chain to disk.
    Run {
        /// Path to the run spec JSON file.
        #[arg(long)]
        spec: PathBuf,
        /// Directory to write the run into. Defaults to
        /// $RECURSIVE_AGENT_RUNS or ~/.local/share/recursive-agent/runs.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a run directory's receipt chain offline.
    Verify {
        /// Path to the run directory.
        #[arg(long)]
        run: PathBuf,
    },
    /// Replay a run from disk. Reads receipts and artifacts, never
    /// re-executes tools, never calls any provider.
    Replay {
        #[arg(long)]
        run: PathBuf,
    },
}

fn default_runs_root() -> PathBuf {
    if let Ok(p) = std::env::var("RECURSIVE_AGENT_RUNS") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("recursive-agent")
        .join("runs")
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor => doctor(),
        Cmd::Run { spec, out } => {
            let raw = match std::fs::read_to_string(&spec) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: cannot read spec {spec:?}: {e}");
                    std::process::exit(2);
                }
            };
            let parsed: RunSpecV1 = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: spec is not a valid RunSpecV1: {e}");
                    std::process::exit(2);
                }
            };
            let out_root = out.unwrap_or_else(default_runs_root);
            match run_spec(&parsed, &out_root) {
                Ok(s) => {
                    println!("run_id: {}", s.run_id);
                    println!("run_dir: {}", s.run_dir.display());
                    println!("chain_length: {}", s.chain_length);
                    println!("chain_head: {}", s.chain_head);
                }
                Err(e) => {
                    eprintln!("error: run failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Verify { run } => verify_cmd(&run),
        Cmd::Replay { run } => replay_cmd(&run),
    }
}

fn doctor() {
    println!("recursive-agent M0");
    println!("mode: recorded-replay-only (no provider)");
    println!("boundary-compiler: 0.1.0");
    println!("stack-ids: 0.1.1");
    println!("bitemporal-runtime: 0.1.0");
    println!("claim-ledger: 0.1.0");
    println!("tools: echo, time_now");
    println!("default runs root: {}", default_runs_root().display());
}

fn verify_cmd(run_dir: &Path) {
    let paths = recursive_agent_ledger::RunPaths::new(run_dir);
    match verify(&paths) {
        Ok(v) => {
            if v.ok {
                println!("verify: ok");
                println!("length: {}", v.length);
                println!("final_head: {}", v.final_head);
                std::process::exit(0);
            } else {
                let Some(d) = v.first_divergence else {
                    eprintln!("verify: internal error: ok=false with no first divergence");
                    std::process::exit(1);
                };
                eprintln!(
                    "verify: FAIL at receipt index {} ({}): expected_head={} observed_head={}",
                    d.index, d.reason, d.expected_head, d.observed_head
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("verify: ERROR: {e}");
            std::process::exit(2);
        }
    }
}

fn replay_cmd(run_dir: &Path) {
    let paths = recursive_agent_ledger::RunPaths::new(run_dir);
    match replay(&paths) {
        Ok(s) => {
            println!("replay: {}", if s.ok { "ok" } else { "FAIL" });
            println!("length: {}", s.length);
            println!("final_head: {}", s.final_head);
            println!("steps: {}", s.step_results.len());
            for st in &s.step_results {
                println!(
                    "  step {} kind={} outcome={} artifacts={}",
                    st.step_id,
                    st.kind,
                    st.outcome,
                    st.artifact_refs.len()
                );
            }
            println!("artifacts: {}", s.artifacts.len());
            for a in &s.artifacts {
                println!("  {a}");
            }
            std::process::exit(if s.ok { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("replay: ERROR: {e}");
            std::process::exit(2);
        }
    }
}
