use thiserror::Error;

/// Fail-closed construction errors for the canonical runtime owner.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeDependencyError {
    /// One or more mandatory owner dependencies were not supplied.
    #[error("missing runtime dependencies: {names:?}")]
    Missing {
        /// Stable dependency labels in validation order.
        names: Vec<&'static str>,
    },
}
