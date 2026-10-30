//! Пайплайн установки RTUN-сервера на VPS. Контракт: docs/deploy-design.md.
//!
//! Порядок шагов: Probe, Upload, Install, Peer, Fetch, Verify. Пайплайн
//! не создает пира повторно: `rt-ctl add-peer` печатает клиентский приватный
//! ключ только один раз, поэтому существующий пир — ошибка `PeerExists`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use rt_proto::wgconf::WgConf;
use rt_proto::{ClientConfig, ServerConfig};

use crate::error::DeployError;
use crate::remote::{ExecOutput, Remote};

const REMOTE_ROOT: &str = "/tmp/rtun-deploy";
const SERVER_CONFIG: &str = "/etc/rtun/server.toml";
const PEERS_DIR: &str = "/etc/rtun/peers";
const SERVER_FILES: [&str; 5] = [
    "install.sh",
    "nftables-rtun.nft",
    "nginx-rtun.conf.template",
    "rtund.service",
    "unbound-rtun.conf",
];
const SERVICES: [&str; 3] = ["rtund", "nginx", "unbound"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Probe,
    Upload,
    Install,
    Peer,
    Fetch,
    Verify,
}

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Self::Probe => "проверка системы",
            Self::Upload => "загрузка файлов",
            Self::Install => "установка сервера",
            Self::Peer => "создание пира",
            Self::Fetch => "получение конфига",
            Self::Verify => "проверка сервисов",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeployPlan {
    /// Корень репозитория: `target/release/{rtund,rt-ctl}` и `packaging/`.
    pub repo_root: PathBuf,
    pub domain: String,
    pub email: String,
    pub peer_name: String,
    pub peer_index: u8,
}

#[derive(Debug, Clone)]
pub struct DeployResult {
    pub peer_name: String,
    pub client_conf: WgConf,
}

#[derive(Debug)]
struct AddedPeer {
    client_private_key: String,
    server_public_key: String,
    psk: Option<String>,
}

pub async fn deploy(
    plan: &DeployPlan,
    remote: &mut dyn Remote,
    progress: &mut (dyn FnMut(Step) + Send),
) -> Result<DeployResult, DeployError> {
    validate_plan(plan)?;

    progress(Step::Probe);
    probe(remote).await?;

    progress(Step::Upload);
    upload(plan, remote).await?;

    progress(Step::Install);
    install(plan, remote).await?;

    progress(Step::Peer);
    let added = add_peer(plan, remote).await?;

    progress(Step::Fetch);
    let server = fetch_server(remote).await?;
    let client = build_client(plan, &added, &server)?;

    progress(Step::Verify);
    verify(remote).await?;

    Ok(DeployResult {
        peer_name: plan.peer_name.clone(),
        client_conf: WgConf::from_client(&client),
    })
}

/// Все значения, которые попадают в shell-команды, проходят строгий allowlist.
pub fn validate_plan(plan: &DeployPlan) -> Result<(), DeployError> {
    if !valid_token(&plan.domain, &['.', '-'], 253) || !plan.domain.contains('.') {
        return Err(DeployError::InvalidInput(format!(
            "domain is not valid: {}",
            plan.domain
        )));
    }
    // Пустой email допустим: certbot зарегистрируется без адреса.
    if !plan.email.is_empty()
        && (!valid_token(&plan.email, &['@', '.', '_', '+', '-'], 254) || !plan.email.contains('@'))
    {
        return Err(DeployError::InvalidInput("email is not valid".into()));
    }
    if !valid_token(&plan.peer_name, &['_', '-'], 32) {
        return Err(DeployError::InvalidInput(format!(
            "peer name must be 1-32 letters, digits, '_' or '-': {}",
            plan.peer_name
        )));
    }
    if !(2..=254).contains(&plan.peer_index) {
        return Err(DeployError::InvalidInput(
            "peer index must be in 2..=254".into(),
        ));
    }
    Ok(())
}

fn valid_token(value: &str, extra: &[char], max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

async fn run(remote: &mut dyn Remote, step: Step, cmd: &str) -> Result<ExecOutput, DeployError> {
    let output = remote.exec(cmd).await?;
    if output.status != 0 {
        return Err(DeployError::StepFailed {
            step,
            status: output.status,
            stderr: output.stderr.trim().to_string(),
        });
    }
    Ok(output)
}

async fn probe(remote: &mut dyn Remote) -> Result<(), DeployError> {
    let arch = run(remote, Step::Probe, "uname -m").await?;
    let arch = arch.stdout.trim();
    if arch != "x86_64" {
        return Err(DeployError::UnsupportedHost(format!(
            "architecture {arch}, need x86_64"
        )));
    }
    let uid = run(remote, Step::Probe, "id -u").await?;
    if uid.stdout.trim() != "0" {
        return Err(DeployError::UnsupportedHost(
            "connect as root; install.sh must run as root".into(),
        ));
    }
    let os = run(remote, Step::Probe, "cat /etc/os-release").await?;
    check_os(&os.stdout)
}

/// Ubuntu 22.04+ или Debian 12+.
pub fn check_os(os_release: &str) -> Result<(), DeployError> {
    let mut id = String::new();
    let mut version = String::new();
    for line in os_release.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"').to_string();
            match key.trim() {
                "ID" => id = value,
                "VERSION_ID" => version = value,
                _ => {}
            }
        }
    }
    let (major, minor) = parse_version(&version).unwrap_or((0, 0));
    let supported = match id.as_str() {
        "ubuntu" => (major, minor) >= (22, 4),
        "debian" => major >= 12,
        _ => false,
    };
    if supported {
        Ok(())
    } else {
        Err(DeployError::UnsupportedHost(format!(
            "{id} {version}; need Ubuntu 22.04+ or Debian 12+"
        )))
    }
}

fn parse_version(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

async fn upload(plan: &DeployPlan, remote: &mut dyn Remote) -> Result<(), DeployError> {
    run(
        remote,
        Step::Upload,
        &format!(
            "rm -rf {REMOTE_ROOT} && mkdir -p {REMOTE_ROOT}/target/release \
             {REMOTE_ROOT}/packaging/server {REMOTE_ROOT}/packaging/decoy"
        ),
    )
    .await?;

    for bin in ["rtund", "rt-ctl"] {
        remote
            .upload(
                &plan.repo_root.join("target").join("release").join(bin),
                &format!("{REMOTE_ROOT}/target/release/{bin}"),
                0o755,
            )
            .await?;
    }
    for file in SERVER_FILES {
        let mode = if file == "install.sh" { 0o755 } else { 0o644 };
        remote
            .upload(
                &plan.repo_root.join("packaging").join("server").join(file),
                &format!("{REMOTE_ROOT}/packaging/server/{file}"),
                mode,
            )
            .await?;
    }
    remote
        .upload(
            &plan
                .repo_root
                .join("packaging")
                .join("decoy")
                .join("index.html"),
            &format!("{REMOTE_ROOT}/packaging/decoy/index.html"),
            0o644,
        )
        .await
}

async fn install(plan: &DeployPlan, remote: &mut dyn Remote) -> Result<(), DeployError> {
    let email_arg = if plan.email.is_empty() {
        String::new()
    } else {
        format!(" --email {}", plan.email)
    };
    run(
        remote,
        Step::Install,
        &format!(
            "cd {REMOTE_ROOT} && bash packaging/server/install.sh --domain {}{email_arg}",
            plan.domain
        ),
    )
    .await?;
    // Временные файлы больше не нужны; ошибку очистки не считаем сбоем деплоя.
    let _ = remote.exec(&format!("rm -rf {REMOTE_ROOT}")).await;
    Ok(())
}

async fn add_peer(plan: &DeployPlan, remote: &mut dyn Remote) -> Result<AddedPeer, DeployError> {
    let peer_file = format!("{PEERS_DIR}/{}.toml", plan.peer_name);
    let exists = remote.exec(&format!("test -f {peer_file}")).await?;
    match exists.status {
        0 => return Err(DeployError::PeerExists(plan.peer_name.clone())),
        1 => {}
        status => {
            return Err(DeployError::StepFailed {
                step: Step::Peer,
                status,
                stderr: exists.stderr.trim().to_string(),
            })
        }
    }

    let output = run(
        remote,
        Step::Peer,
        &format!(
            "runuser -u rtun -- rt-ctl add-peer --peers-dir {PEERS_DIR} --name {} --index {} --psk \
             --server-config {SERVER_CONFIG}",
            plan.peer_name, plan.peer_index
        ),
    )
    .await?;
    let added = parse_add_peer(&output.stdout)?;
    run(remote, Step::Peer, "systemctl reload rtund").await?;
    Ok(added)
}

/// Разбирает вывод `rt-ctl add-peer`. Формат: строки `key: value`.
fn parse_add_peer(stdout: &str) -> Result<AddedPeer, DeployError> {
    let mut client_private_key = None;
    let mut server_public_key = None;
    let mut psk = None;
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("client private key: ") {
            client_private_key = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("server public key: ") {
            server_public_key = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("preshared key: ") {
            psk = Some(value.trim().to_string());
        }
    }
    match (client_private_key, server_public_key) {
        (Some(client_private_key), Some(server_public_key)) => Ok(AddedPeer {
            client_private_key,
            server_public_key,
            psk,
        }),
        _ => Err(DeployError::Parse(
            "add-peer output has no client private key or server public key".into(),
        )),
    }
}

async fn fetch_server(remote: &mut dyn Remote) -> Result<ServerConfig, DeployError> {
    let bytes = remote.download(SERVER_CONFIG).await?;
    let text = String::from_utf8(bytes)
        .map_err(|error| DeployError::Parse(format!("server config is not UTF-8: {error}")))?;
    ServerConfig::from_toml(&text).map_err(|error| DeployError::Parse(error.to_string()))
}

fn build_client(
    plan: &DeployPlan,
    added: &AddedPeer,
    server: &ServerConfig,
) -> Result<ClientConfig, DeployError> {
    let mut cfg = ClientConfig::default();
    cfg.endpoint.host = plan.domain.clone();
    cfg.device.private_key = added.client_private_key.clone();
    cfg.device.peer_public_key = added.server_public_key.clone();
    cfg.device.preshared_key = added.psk.clone();
    cfg.device.address_v4 = Ipv4Addr::new(10, 66, 0, plan.peer_index);
    cfg.device.address_v6 = Ipv6Addr::new(0xfd66, 1, 0, 0, 0, 0, 0, plan.peer_index.into());
    // obfs-параметры обязаны совпадать с сервером.
    cfg.obfs = server.obfs.clone();
    cfg.validate()
        .map_err(|error| DeployError::Config(error.to_string()))?;
    Ok(cfg)
}

async fn verify(remote: &mut dyn Remote) -> Result<(), DeployError> {
    let cmd = format!("systemctl is-active {}", SERVICES.join(" "));
    let output = run(remote, Step::Verify, &cmd).await?;
    let states: Vec<&str> = output.stdout.lines().map(str::trim).collect();
    if states.len() != SERVICES.len() || states.iter().any(|state| *state != "active") {
        return Err(DeployError::StepFailed {
            step: Step::Verify,
            status: 0,
            stderr: format!("services not active: {}", output.stdout.trim()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::MockRemote;
    use rt_proto::keys::generate_private_key;
    use rt_proto::ObfsParams;

    const UBUNTU_OK: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n";

    fn plan() -> DeployPlan {
        DeployPlan {
            repo_root: PathBuf::from("/repo"),
            domain: "vpn.example.com".into(),
            email: "admin@example.com".into(),
            peer_name: "laptop".into(),
            peer_index: 2,
        }
    }

    fn server_toml() -> String {
        ServerConfig {
            private_key: generate_private_key(),
            obfs: ObfsParams::generate(),
            ..ServerConfig::default()
        }
        .to_toml()
        .unwrap()
    }

    fn happy_remote() -> MockRemote {
        let mut remote = MockRemote::new();
        remote.rule("uname -m", 0, "x86_64\n", "");
        remote.rule("id -u", 0, "0\n", "");
        remote.rule("cat /etc/os-release", 0, UBUNTU_OK, "");
        remote.rule("rm -rf /tmp/rtun-deploy", 0, "", "");
        remote.rule("cd /tmp/rtun-deploy && bash", 0, "", "");
        remote.rule("test -f /etc/rtun/peers/", 1, "", "");
        let peer_out = format!(
            "peer laptop written\nclient private key: {}\nserver public key: {}\npreshared key: {}\n",
            generate_private_key(),
            generate_private_key(),
            generate_private_key(),
        );
        remote.rule("runuser -u rtun -- rt-ctl add-peer", 0, &peer_out, "");
        remote.rule("systemctl reload rtund", 0, "", "");
        remote.rule("systemctl is-active", 0, "active\nactive\nactive\n", "");
        remote
            .files
            .insert(SERVER_CONFIG.into(), server_toml().into_bytes());
        remote
    }

    #[tokio::test]
    async fn full_deploy_runs_all_steps_in_order() {
        let mut remote = happy_remote();
        let mut steps = Vec::new();
        let result = deploy(&plan(), &mut remote, &mut |step| steps.push(step))
            .await
            .unwrap();
        assert_eq!(
            steps,
            [
                Step::Probe,
                Step::Upload,
                Step::Install,
                Step::Peer,
                Step::Fetch,
                Step::Verify
            ]
        );
        assert_eq!(result.client_conf.peer.endpoint_host, "vpn.example.com");
        assert_eq!(result.client_conf.rtun.ws_path, "/ws");
        assert!(result.client_conf.peer.preshared_key.is_some());
        assert!(result.client_conf.into_client().is_ok());
        let peer = remote
            .commands
            .iter()
            .position(|cmd| cmd.starts_with("runuser -u rtun -- rt-ctl add-peer"))
            .unwrap();
        let reload = remote
            .commands
            .iter()
            .position(|cmd| cmd == "systemctl reload rtund")
            .unwrap();
        assert!(peer < reload);
    }

    #[tokio::test]
    async fn uploads_binaries_and_install_script_with_modes() {
        let mut remote = happy_remote();
        deploy(&plan(), &mut remote, &mut |_| {}).await.unwrap();
        assert!(remote
            .uploads
            .contains(&("/tmp/rtun-deploy/target/release/rtund".into(), 0o755)));
        assert!(remote
            .uploads
            .contains(&("/tmp/rtun-deploy/packaging/server/install.sh".into(), 0o755)));
        assert!(remote
            .uploads
            .contains(&("/tmp/rtun-deploy/packaging/decoy/index.html".into(), 0o644)));
    }

    #[tokio::test]
    async fn arm_host_is_rejected_at_probe() {
        let mut remote = MockRemote::new();
        remote.rule("uname -m", 0, "aarch64\n", "");
        let error = deploy(&plan(), &mut remote, &mut |_| {}).await.unwrap_err();
        assert!(matches!(error, DeployError::UnsupportedHost(_)), "{error}");
        assert!(!remote.commands.iter().any(|cmd| cmd.contains("install.sh")));
    }

    #[test]
    fn old_ubuntu_is_rejected() {
        let error = check_os("ID=ubuntu\nVERSION_ID=\"20.04\"\n").unwrap_err();
        assert!(matches!(error, DeployError::UnsupportedHost(_)));
        assert!(check_os("ID=debian\nVERSION_ID=\"12\"\n").is_ok());
        assert!(check_os("ID=ubuntu\nVERSION_ID=\"22.04\"\n").is_ok());
        assert!(check_os("ID=fedora\nVERSION_ID=\"40\"\n").is_err());
    }

    #[tokio::test]
    async fn install_failure_reports_step_and_stderr() {
        let mut remote = happy_remote();
        remote.clear_rules();
        remote.rule("uname -m", 0, "x86_64\n", "");
        remote.rule("id -u", 0, "0\n", "");
        remote.rule("cat /etc/os-release", 0, UBUNTU_OK, "");
        remote.rule("rm -rf /tmp/rtun-deploy", 0, "", "");
        remote.rule("cd /tmp/rtun-deploy && bash", 100, "", "apt failed");
        let error = deploy(&plan(), &mut remote, &mut |_| {}).await.unwrap_err();
        match error {
            DeployError::StepFailed {
                step,
                status,
                stderr,
            } => {
                assert_eq!(step, Step::Install);
                assert_eq!(status, 100);
                assert_eq!(stderr, "apt failed");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn existing_peer_is_not_recreated() {
        let mut remote = happy_remote();
        remote.rule_first("test -f", 0, "", "");
        let error = deploy(&plan(), &mut remote, &mut |_| {}).await.unwrap_err();
        assert!(matches!(error, DeployError::PeerExists(name) if name == "laptop"));
        assert!(!remote.commands.iter().any(|cmd| cmd.contains("add-peer")));
    }

    #[tokio::test]
    async fn peer_reload_failure_stops_deployment() {
        let mut remote = happy_remote();
        remote.rule_first("systemctl reload rtund", 1, "", "reload failed");
        let error = deploy(&plan(), &mut remote, &mut |_| {}).await.unwrap_err();
        assert!(matches!(
            error,
            DeployError::StepFailed {
                step: Step::Peer,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn invalid_input_never_reaches_the_shell() {
        let mut remote = happy_remote();
        let mut bad = plan();
        bad.domain = "vpn.example.com;rm -rf /".into();
        let error = deploy(&bad, &mut remote, &mut |_| {}).await.unwrap_err();
        assert!(matches!(error, DeployError::InvalidInput(_)));
        assert!(remote.commands.is_empty());

        let mut bad_peer = plan();
        bad_peer.peer_name = "../etc".into();
        assert!(matches!(
            validate_plan(&bad_peer),
            Err(DeployError::InvalidInput(_))
        ));
    }

    #[test]
    fn add_peer_output_without_keys_is_a_parse_error() {
        assert!(matches!(
            parse_add_peer("peer written\n"),
            Err(DeployError::Parse(_))
        ));
    }
}
