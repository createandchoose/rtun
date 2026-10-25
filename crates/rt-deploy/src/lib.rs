//! Установка RTUN-сервера на VPS. Контракт: docs/deploy-design.md.

pub mod error;
pub mod pipeline;
pub mod remote;

pub use error::DeployError;
pub use pipeline::{deploy, DeployPlan, DeployResult, Step};
pub use remote::{ExecOutput, MockRemote, Remote};
