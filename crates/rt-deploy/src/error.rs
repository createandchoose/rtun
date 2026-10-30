use thiserror::Error;

use crate::pipeline::Step;

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported host: {0}")]
    UnsupportedHost(String),
    #[error("step {step:?} failed with status {status}: {stderr}")]
    StepFailed {
        step: Step,
        status: i32,
        stderr: String,
    },
    #[error("peer {0} already exists on the server; its client key cannot be issued again")]
    PeerExists(String),
    #[error("cannot parse remote output: {0}")]
    Parse(String),
    #[error("remote transport error: {0}")]
    Remote(String),
    #[error("generated configuration is invalid: {0}")]
    Config(String),
}
