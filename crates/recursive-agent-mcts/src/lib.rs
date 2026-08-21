//! Deterministic, bounded UCT search over tool sequences.
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
pub type ScoreFn = Box<dyn Fn(&[&str]) -> f64>;

pub struct McstSearch {
    available_tools: Vec<(String, serde_json::Value)>,
}
impl McstSearch {
    pub fn new(mut available_tools: Vec<(String, serde_json::Value)>) -> Result<Self, McstError> {
        if available_tools.is_empty() {
            return Err(McstError::NoMoves);
        }
        available_tools.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self { available_tools })
    }
    pub fn search(&self, score_fn: &ScoreFn, iterations: usize) -> McstNode {
        self.search_bounded(score_fn, iterations, 1, 0)
    }
    pub fn search_bounded(
        &self,
        score_fn: &ScoreFn,
        iterations: usize,
        max_depth: usize,
        seed: u64,
    ) -> McstNode {
        let mut root = McstNode::new("root", serde_json::Value::Null);
        let budget = iterations.min(100_000);
        let depth = max_depth.clamp(1, 64);
        for i in 0..budget {
            let mut path = Vec::new();
            let mut node = &mut root;
            for d in 0..depth {
                if node.children.len() < self.available_tools.len() {
                    let idx = (splitmix(seed.wrapping_add(i as u64).wrapping_add(d as u64))
                        as usize)
                        % self.available_tools.len();
                    let (name, args) = &self.available_tools[idx];
                    if !node.children.iter().any(|c| c.tool_name == *name) {
                        node.children.push(McstNode::new(name, args.clone()));
                    }
                }
                let idx = node
                    .children
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| {
                        uct(a, node.visits)
                            .total_cmp(&uct(b, node.visits))
                            .then_with(|| b.tool_name.cmp(&a.tool_name))
                    })
                    .map(|(j, _)| j)
                    .unwrap_or(0);
                path.push(node.children[idx].tool_name.clone());
                node = &mut node.children[idx];
                if d + 1 == depth {
                    break;
                }
            }
            let refs = path.iter().map(String::as_str).collect::<Vec<_>>();
            let score = score_fn(&refs);
            root.visits += 1;
            root.total_score += score;
            update_path(&mut root, &path, score);
        }
        root
    }
    pub fn best_path(root: &McstNode) -> Vec<String> {
        let mut out = Vec::new();
        let mut n = root;
        while let Some(c) = n.children.iter().filter(|c| c.visits > 0).max_by(|a, b| {
            (a.total_score / a.visits as f64)
                .total_cmp(&(b.total_score / b.visits as f64))
                .then_with(|| b.tool_name.cmp(&a.tool_name))
        }) {
            out.push(c.tool_name.clone());
            n = c;
        }
        out
    }
}
fn update_path(node: &mut McstNode, path: &[String], score: f64) {
    if let Some((name, rest)) = path.split_first() {
        if let Some(child) = node.children.iter_mut().find(|c| c.tool_name == *name) {
            child.visits += 1;
            child.total_score += score;
            update_path(child, rest, score);
        }
    }
}
fn uct(n: &McstNode, parent: u64) -> f64 {
    if n.visits == 0 {
        return f64::INFINITY;
    }
    n.total_score / n.visits as f64
        + std::f64::consts::SQRT_2 * ((parent.max(1) as f64).ln() / n.visits as f64).sqrt()
}
fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let s = McstSearch::new(vec![
            ("b".into(), serde_json::Value::Null),
            ("a".into(), serde_json::Value::Null),
        ])?;
        let f: ScoreFn = Box::new(|p| if p[0] == "a" { 1.0 } else { 0.0 });
        let a = s.search_bounded(&f, 100, 2, 7);
        let b = s.search_bounded(&f, 100, 2, 7);
        assert_eq!(serde_json::to_string(&a)?, serde_json::to_string(&b)?);
        assert_eq!(McstSearch::best_path(&a)[0], "a");
        Ok(())
    }
}
