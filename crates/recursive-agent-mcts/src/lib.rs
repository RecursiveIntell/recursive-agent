#![cfg(feature = "later-phase-prototype")]

//! Monte Carlo Tree Search over tool sequences.
//! Selects tools via random sampling, scores via provided function,
//! returns the best tool found.

use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McstError {
    #[error("no moves available")]
    NoMoves,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McstNode {
    pub tool_name: String,
    pub visits: u64,
    pub total_score: f64,
    pub children: Vec<McstNode>,
    pub args_template: serde_json::Value,
}

impl McstNode {
    pub fn new(tool_name: &str, args_template: serde_json::Value) -> Self {
        Self {
            tool_name: tool_name.into(),
            visits: 0,
            total_score: 0.0,
            children: Vec::new(),
            args_template,
        }
    }
}

/// Scoring function: takes a sequence of tool names and returns a score.
pub type ScoreFn = Box<dyn Fn(&[&str]) -> f64>;

pub struct McstSearch {
    available_tools: Vec<(String, serde_json::Value)>,
}

impl McstSearch {
    pub fn new(available_tools: Vec<(String, serde_json::Value)>) -> Result<Self, McstError> {
        if available_tools.is_empty() {
            return Err(McstError::NoMoves);
        }
        Ok(Self { available_tools })
    }

    /// Run `iterations` rollouts, scoring each randomly-selected tool.
    pub fn search(&self, score_fn: &ScoreFn, iterations: usize) -> McstNode {
        let mut rng = rand::thread_rng();
        let mut best_score = f64::NEG_INFINITY;
        let mut best_tool = String::new();
        let mut total_visits = 0u64;

        for _ in 0..iterations {
            let idx = rng.gen_range(0..self.available_tools.len());
            let (tool_name, _args) = &self.available_tools[idx];
            let tool_names = vec![tool_name.as_str()];
            let score = score_fn(&tool_names);
            total_visits += 1;
            if score > best_score {
                best_score = score;
                best_tool = tool_name.clone();
            }
        }

        let mut root = McstNode::new("root", serde_json::Value::Null);
        root.visits = total_visits;
        root.total_score = best_score;
        if !best_tool.is_empty() {
            root.children
                .push(McstNode::new(&best_tool, serde_json::Value::Null));
        }
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_with_one_tool() -> Result<(), McstError> {
        let tools = vec![("echo".into(), serde_json::json!({"text": "hi"}))];
        let mcts = McstSearch::new(tools)?;
        let score_fn: ScoreFn = Box::new(|_tools| 1.0);
        let result = mcts.search(&score_fn, 10);
        assert!(result.visits > 0);
        Ok(())
    }

    #[test]
    fn empty_tools_fails() {
        let result = McstSearch::new(vec![]);
        assert!(result.is_err());
    }
}
