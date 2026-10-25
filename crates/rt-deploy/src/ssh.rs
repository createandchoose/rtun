//! Настоящий SSH-транспорт для деплоя на VPS (крейт `russh`).
//! Контракт: docs/deploy-design.md.
//!
//! Пароль и приватный ключ не логируются и не пишутся на диск. Команды
//! выполняются через exec-канал; файлы передаются через stdin команды `cat`,
//! поэтому SFTP-подсистема не нужна.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, AuthResult, Handle};
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};

use crate::error::DeployError;
use crate::remote::{ExecOutput, Remote};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_MAX: usize = 4;
const MAX_HOST_LEN: usize = 253;
const MAX_USER_LEN: usize = 32;

/// Способ аутентификации на VPS.
pub enum SshAuth {
    /// Пароль пользователя. Живет в памяти только на время подключения.
    Password(String),
    /// Путь к приватному ключу OpenSSH. Ключ с парольной фразой не поддерживается.
    KeyFile(PathBuf),
}

impl fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshAuth::Password(_) => f.write_str("Password(<redacted>)"),
            SshAuth::KeyFile(path) => f.debug_tuple("KeyFile").field(path).finish(),
        }
    }
}

/// Адрес VPS и пользователь для SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpsTarget {
    /// IP-адрес или домен.
    pub host: String,
    /// TCP-порт SSH, обычно 22.
    pub port: u16,
    /// Пользователь SSH, обычно root.
    pub user: String,
}

impl VpsTarget {
    /// Проверяет поля до любых сетевых операций.
    pub fn validate(&self) -> Result<(), DeployError> {
        validate_host(&self.host)?;
        if self.port == 0 {
            return Err(invalid("SSH port must be in 1..=65535"));
        }
        validate_user(&self.user)
    }
}

fn invalid(msg: &str) -> DeployError {
    DeployError::InvalidInput(msg.to_string())
}

fn remote_err(msg: impl Into<String>) -> DeployError {
    DeployError::Remote(msg.into())
}

fn validate_host(host: &str) -> Result<(), DeployError> {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(invalid("host must be 1..=253 characters"));
    }
    let allowed = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    if !allowed || host.starts_with('-') {
        return Err(invalid(&format!(
            "host {host:?} must be an IP address or a domain name"
        )));
    }
    Ok(())
}

fn validate_user(user: &str) -> Result<(), DeployError> {
    if user.is_empty() || user.len() > MAX_USER_LEN {
        return Err(invalid("SSH user must be 1..=32 characters"));
    }
    let allowed = user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !allowed || user.starts_with('-') {
        return Err(invalid(&format!(
            "SSH user {user:?} has invalid characters"
        )));
    }
    Ok(())
}

/// Обработчик событий клиента russh.
///
/// Ключ сервера принимается без сверки с known_hosts. SHA256-отпечаток
/// логируется через tracing::info, чтобы его можно было сверить вручную.
/// Защиты от MITM при повторных подключениях это не дает (TOFU без хранения).
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(cert) => {
                cert.public_key().fingerprint(HashAlg::Sha256)
            }
        };
        tracing::info!(%fingerprint, "SSH host key accepted without known_hosts check");
        Ok(true)
    }
}

/// SSH-подключение к VPS, реализующее [`Remote`].
pub struct RusshRemote {
    handle: Handle<ClientHandler>,
}

/// Сырой результат выполнения команды; stdout и stderr без преобразования.
struct RawOutput {
    /// -1, если сервер не прислал exit-status (например, команда убита сигналом).
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RusshRemote {
    /// Подключается к `target` и проходит аутентификацию.
    ///
    /// Ошибки сети и аутентификации возвращаются как `DeployError::Remote`
    /// без пароля и содержимого ключа.
    pub async fn connect(target: &VpsTarget, auth: &SshAuth) -> Result<RusshRemote, DeployError> {
        target.validate()?;

        let config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX,
            ..client::Config::default()
        });
        let addr = (target.host.as_str(), target.port);
        tracing::info!(host = %target.host, port = target.port, user = %target.user, "connecting over SSH");

        let mut handle = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            client::connect(config, addr, ClientHandler),
        )
        .await
        {
            Err(_) => {
                return Err(remote_err(format!(
                    "connection to {}:{} timed out after {}s",
                    target.host,
                    target.port,
                    CONNECT_TIMEOUT.as_secs()
                )))
            }
            Ok(Err(e)) => {
                return Err(remote_err(format!(
                    "cannot connect to {}:{}: {e}",
                    target.host, target.port
                )))
            }
            Ok(Ok(handle)) => handle,
        };

        let result = match auth {
            SshAuth::Password(password) => {
                handle
                    .authenticate_password(target.user.as_str(), password.as_str())
                    .await
            }
            SshAuth::KeyFile(path) => {
                let key = keys::load_secret_key(path, None).map_err(|e| {
                    remote_err(format!("cannot load SSH key {}: {e}", path.display()))
                })?;
                let hash_alg = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| remote_err(format!("server signature negotiation failed: {e}")))?
                    .flatten();
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                handle
                    .authenticate_publickey(target.user.as_str(), key)
                    .await
            }
        };
        let result =
            result.map_err(|e| remote_err(format!("authentication request failed: {e}")))?;
        if !matches!(result, AuthResult::Success) {
            return Err(remote_err(format!(
                "authentication failed for user {}",
                target.user
            )));
        }
        tracing::info!(host = %target.host, "SSH authentication succeeded");

        Ok(RusshRemote { handle })
    }

    /// Закрывает SSH-соединение.
    pub async fn close(self) -> Result<(), DeployError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| remote_err(format!("disconnect failed: {e}")))
    }

    /// Выполняет команду в exec-канале. Если передан `stdin`, файл подается
    /// на stdin команды.
    async fn run(&mut self, cmd: &str, stdin: Option<&Path>) -> Result<RawOutput, DeployError> {
        // Файл открывается до запуска команды: иначе при ошибке команда
        // (например, `cat > file`) создала бы пустой файл на сервере.
        let input = match stdin {
            Some(path) => Some(
                tokio::fs::File::open(path)
                    .await
                    .map_err(|e| remote_err(format!("cannot read {}: {e}", path.display())))?,
            ),
            None => None,
        };

        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| remote_err(format!("cannot open SSH session channel: {e}")))?;
        channel
            .exec(true, cmd.as_bytes().to_vec())
            .await
            .map_err(|e| remote_err(format!("cannot start remote command: {e}")))?;

        if let Some(file) = input {
            channel
                .data(file)
                .await
                .map_err(|e| remote_err(format!("cannot send data to remote command: {e}")))?;
            channel
                .eof()
                .await
                .map_err(|e| remote_err(format!("cannot close remote stdin: {e}")))?;
        }

        let mut out = RawOutput {
            status: -1,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => out.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => {
                    out.status = i32::try_from(exit_status).unwrap_or(-1);
                }
                ChannelMsg::Failure => {
                    return Err(remote_err("server refused to run the remote command"));
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Квотирует строку для POSIX-шелла, одинарными кавычками.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ensure_success(out: &RawOutput, what: &str) -> Result<(), DeployError> {
    if out.status == 0 {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(remote_err(format!(
        "{what} failed with status {}: {}",
        out.status,
        stderr.trim()
    )))
}

#[async_trait]
impl Remote for RusshRemote {
    async fn exec(&mut self, cmd: &str) -> Result<ExecOutput, DeployError> {
        let out = self.run(cmd, None).await?;
        Ok(ExecOutput {
            status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    async fn upload(&mut self, local: &Path, remote: &str, mode: u32) -> Result<(), DeployError> {
        if mode > 0o7777 {
            return Err(invalid(&format!("file mode {mode:o} is out of range")));
        }
        // Пишем во временный файл и переименовываем: частично записанный
        // файл не появляется под целевым именем.
        let tmp = format!("{remote}.rtun-part");
        let (tmp_q, remote_q) = (shell_quote(&tmp), shell_quote(remote));
        let cmd = format!(
            "cat > {tmp_q} && chmod {mode:o} {tmp_q} && mv -f {tmp_q} {remote_q} || {{ rm -f {tmp_q}; false; }}"
        );
        let out = self.run(&cmd, Some(local)).await?;
        ensure_success(&out, &format!("upload to {remote}"))
    }

    async fn download(&mut self, remote: &str) -> Result<Vec<u8>, DeployError> {
        let out = self
            .run(&format!("cat {}", shell_quote(remote)), None)
            .await?;
        ensure_success(&out, &format!("download of {remote}"))?;
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16, user: &str) -> VpsTarget {
        VpsTarget {
            host: host.to_string(),
            port,
            user: user.to_string(),
        }
    }

    #[test]
    fn validate_accepts_ip_and_domain() {
        for t in [
            target("203.0.113.10", 22, "root"),
            target("vpn.example.com", 2222, "deploy_user"),
            target("::1", 22, "ubuntu"),
        ] {
            assert!(t.validate().is_ok(), "{t:?} should be valid");
        }
    }

    #[test]
    fn validate_rejects_bad_host() {
        for host in ["", "-x", "a b", "host;rm -rf /", "a/b", "$(id)"] {
            let err = target(host, 22, "root").validate().unwrap_err();
            assert!(matches!(err, DeployError::InvalidInput(_)), "host {host:?}");
        }
    }

    #[test]
    fn validate_rejects_port_zero() {
        assert!(matches!(
            target("example.com", 0, "root").validate(),
            Err(DeployError::InvalidInput(_))
        ));
    }

    #[test]
    fn validate_rejects_bad_user() {
        for user in ["", "-root", "ro ot", "r;m", "a@b"] {
            let err = target("example.com", 22, user).validate().unwrap_err();
            assert!(matches!(err, DeployError::InvalidInput(_)), "user {user:?}");
        }
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("/etc/rtun"), "'/etc/rtun'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn debug_does_not_show_password() {
        let auth = SshAuth::Password("hunter2-secret".to_string());
        let shown = format!("{auth:?}");
        assert!(!shown.contains("hunter2"), "password leaked: {shown}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn ensure_success_reports_stderr() {
        let out = RawOutput {
            status: 2,
            stdout: Vec::new(),
            stderr: b"cat: /nope: No such file\n".to_vec(),
        };
        let err = ensure_success(&out, "download").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("status 2"), "{text}");
        assert!(text.contains("No such file"), "{text}");
    }

    #[tokio::test]
    async fn connect_rejects_invalid_target_without_network() {
        let err = match RusshRemote::connect(
            &target("", 22, "root"),
            &SshAuth::Password("x".to_string()),
        )
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("empty host must not connect"),
        };
        assert!(matches!(err, DeployError::InvalidInput(_)));
    }

    /// Ручной запуск против настоящего VPS:
    /// RTUN_TEST_SSH_HOST, RTUN_TEST_SSH_USER, RTUN_TEST_SSH_KEY (путь к ключу),
    /// необязательно RTUN_TEST_SSH_PORT (по умолчанию 22).
    /// cargo test -p rt-deploy -- --ignored
    #[tokio::test]
    #[ignore = "needs a real SSH server: RTUN_TEST_SSH_HOST, RTUN_TEST_SSH_USER, RTUN_TEST_SSH_KEY"]
    async fn real_server_exec_upload_download() {
        let host = std::env::var("RTUN_TEST_SSH_HOST").expect("RTUN_TEST_SSH_HOST is not set");
        let user = std::env::var("RTUN_TEST_SSH_USER").expect("RTUN_TEST_SSH_USER is not set");
        let key = std::env::var("RTUN_TEST_SSH_KEY").expect("RTUN_TEST_SSH_KEY is not set");
        let port = match std::env::var("RTUN_TEST_SSH_PORT") {
            Ok(p) => p.parse().expect("RTUN_TEST_SSH_PORT must be a number"),
            Err(_) => 22,
        };
        let target = VpsTarget { host, port, user };

        let mut remote = RusshRemote::connect(&target, &SshAuth::KeyFile(PathBuf::from(key)))
            .await
            .expect("connect");

        let uname = remote.exec("uname -m").await.expect("exec");
        assert_eq!(uname.status, 0, "stderr: {}", uname.stderr);
        assert!(!uname.stdout.trim().is_empty());

        let pid = std::process::id();
        let local = std::env::temp_dir().join(format!("rtun-ssh-test-{pid}"));
        std::fs::write(&local, b"rtun ssh test\n").expect("write local file");
        let remote_path = format!("/tmp/rtun-ssh-test-{pid}");

        remote
            .upload(&local, &remote_path, 0o600)
            .await
            .expect("upload");
        let bytes = remote.download(&remote_path).await.expect("download");
        assert_eq!(bytes, b"rtun ssh test\n");

        let rm = remote
            .exec(&format!("rm -f {}", shell_quote(&remote_path)))
            .await
            .expect("cleanup");
        assert_eq!(rm.status, 0);
        let _ = std::fs::remove_file(&local);
        remote.close().await.expect("close");
    }
}
