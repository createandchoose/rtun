use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;

use crate::error::DeployError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Удаленная машина, на которой выполняется деплой.
/// Реализация по SSH будет добавлена отдельно; здесь только контракт и мок.
#[async_trait]
pub trait Remote: Send {
    async fn exec(&mut self, cmd: &str) -> Result<ExecOutput, DeployError>;
    async fn upload(&mut self, local: &Path, remote: &str, mode: u32) -> Result<(), DeployError>;
    async fn download(&mut self, remote: &str) -> Result<Vec<u8>, DeployError>;
}

/// Мок для тестов и dry-run. Команды сопоставляются по префиксу, первое
/// совпадение побеждает. Неизвестная команда возвращает статус 127.
#[derive(Debug, Default)]
pub struct MockRemote {
    rules: Vec<(String, ExecOutput)>,
    pub commands: Vec<String>,
    pub uploads: Vec<(String, u32)>,
    pub files: HashMap<String, Vec<u8>>,
}

impl MockRemote {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rule(&mut self, prefix: &str, status: i32, stdout: &str, stderr: &str) {
        self.rules
            .push((prefix.to_string(), output(status, stdout, stderr)));
    }

    /// Правило, которое проверяется раньше всех остальных.
    pub fn rule_first(&mut self, prefix: &str, status: i32, stdout: &str, stderr: &str) {
        self.rules
            .insert(0, (prefix.to_string(), output(status, stdout, stderr)));
    }

    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }
}

fn output(status: i32, stdout: &str, stderr: &str) -> ExecOutput {
    ExecOutput {
        status,
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

#[async_trait]
impl Remote for MockRemote {
    async fn exec(&mut self, cmd: &str) -> Result<ExecOutput, DeployError> {
        self.commands.push(cmd.to_string());
        let found = self
            .rules
            .iter()
            .find(|(prefix, _)| cmd.starts_with(prefix.as_str()))
            .map(|(_, output)| output.clone());
        Ok(found.unwrap_or_else(|| ExecOutput {
            status: 127,
            stdout: String::new(),
            stderr: format!("mock: no rule for command: {cmd}"),
        }))
    }

    async fn upload(&mut self, _local: &Path, remote: &str, mode: u32) -> Result<(), DeployError> {
        self.uploads.push((remote.to_string(), mode));
        Ok(())
    }

    async fn download(&mut self, remote: &str) -> Result<Vec<u8>, DeployError> {
        self.files
            .get(remote)
            .cloned()
            .ok_or_else(|| DeployError::Remote(format!("no such file: {remote}")))
    }
}
