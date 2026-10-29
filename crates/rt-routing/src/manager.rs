use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::{Result, RoutingError};
use crate::nft::{
    cleanup_ip_commands, client_ip6_commands, client_ip_commands, client_nft, kill_switch_nft,
    plan_direct_routes, route_batch_lines, server_nft, set_add_command, ClientPlan, DirectRoute,
};
use crate::win::{self, PhysicalRoute, WinRoute};

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput>;
}

pub struct ProcessExecutor;

#[async_trait]
impl CommandExecutor for ProcessExecutor {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|error| RoutingError::Command {
                program: program.to_string(),
                args: args.to_vec(),
                stderr: error.to_string(),
            })?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AppliedMode {
    Client,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedState {
    pub mode: AppliedMode,
    pub tun_name: String,
    pub table_id: u32,
    pub mark: u32,
    pub kill_switch: bool,
}

#[derive(Debug, Clone)]
pub struct ServerPlan {
    pub tun_name: String,
    pub mtu: u16,
    pub v4: Ipv4Net,
    pub v6: Ipv6Net,
    pub v4_address: std::net::Ipv4Addr,
    pub v6_address: std::net::Ipv6Addr,
    pub udp_port: u16,
    pub handshake_rate: u32,
}

pub struct RuleManager {
    executor: Arc<dyn CommandExecutor>,
    state_path: PathBuf,
    run_dir: PathBuf,
    apply_lock: Mutex<()>,
    win_routes: Mutex<Vec<WinRoute>>,
}

impl RuleManager {
    pub fn new(
        executor: Arc<dyn CommandExecutor>,
        state_path: impl Into<PathBuf>,
        run_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            executor,
            state_path: state_path.into(),
            run_dir: run_dir.into(),
            apply_lock: Mutex::new(()),
            win_routes: Mutex::new(Vec::new()),
        }
    }

    pub fn with_process() -> Self {
        Self::new(
            Arc::new(ProcessExecutor),
            "/run/rtun/client-state.json",
            "/run/rtun",
        )
    }

    pub async fn recover(&self) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        self.cleanup_known().await;
        let _ = std::fs::remove_file(&self.state_path);
        Ok(())
    }

    async fn cleanup_known(&self) {
        let state = self.state().ok().flatten();
        let mark = state
            .as_ref()
            .map(|state| state.mark)
            .filter(|mark| *mark != 0)
            .unwrap_or(1);
        let table_id = state
            .as_ref()
            .map(|state| state.table_id)
            .filter(|table| *table != 0)
            .unwrap_or(51820);
        for table in ["rtun", "rtun_ks", "rtun_srv"] {
            let _ = self
                .executor
                .run("nft", &strings(&["delete", "table", "inet", table]))
                .await;
        }
        let mark = format!("{mark:#x}");
        let table_id = table_id.to_string();
        for args in [
            vec![
                "rule".to_string(),
                "del".into(),
                "pref".into(),
                "100".into(),
                "fwmark".into(),
                mark,
                "lookup".into(),
                "main".into(),
            ],
            vec![
                "rule".to_string(),
                "del".into(),
                "pref".into(),
                "200".into(),
                "lookup".into(),
                table_id.clone(),
            ],
        ] {
            let _ = self.executor.run("ip", &args).await;
            let mut v6 = vec!["-6".to_string()];
            v6.extend(args);
            let _ = self.executor.run("ip", &v6).await;
        }
        let _ = self
            .executor
            .run("ip", &strings(&["route", "flush", "table", &table_id]))
            .await;
        let mut v6 = vec!["-6".to_string()];
        v6.extend(strings(&["route", "flush", "table", &table_id]));
        let _ = self.executor.run("ip", &v6).await;
    }

    pub async fn apply_client(&self, plan: &ClientPlan) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        self.write_state(&AppliedState {
            mode: AppliedMode::Client,
            tun_name: plan.tun_name.clone(),
            table_id: plan.table_id,
            mark: plan.mark,
            kill_switch: plan.kill_switch,
        })?;
        let result = self.apply_client_inner(plan).await;
        if result.is_err() {
            self.cleanup_client_inner(plan).await;
            let _ = std::fs::remove_file(&self.state_path);
        }
        result
    }

    async fn apply_client_inner(&self, plan: &ClientPlan) -> Result<()> {
        self.apply_ruleset("rtun", &client_nft(plan)).await?;
        self.ip("ip", &client_ip_commands(plan)).await?;
        self.ip("ip -6", &client_ip6_commands(plan)).await?;
        if plan.kill_switch {
            self.apply_ruleset("rtun_ks", &kill_switch_nft(plan))
                .await?;
        }
        Ok(())
    }

    pub async fn cleanup_client(&self, plan: &ClientPlan) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        self.cleanup_client_inner(plan).await;
        let _ = std::fs::remove_file(&self.state_path);
        Ok(())
    }

    async fn cleanup_client_inner(&self, plan: &ClientPlan) {
        if cfg!(windows) {
            self.remove_windows_routes().await;
            return;
        }
        let _ = self
            .executor
            .run("nft", &strings(&["delete", "table", "inet", "rtun_ks"]))
            .await;
        let _ = self
            .executor
            .run("nft", &strings(&["delete", "table", "inet", "rtun"]))
            .await;
        let owned = cleanup_ip_commands(plan);
        let _ = self.ip("ip", &owned).await;
        let _ = self.ip("ip -6", &owned).await;
    }

    pub async fn configure_interface(
        &self,
        tun_name: &str,
        mtu: u16,
        v4: Ipv4Net,
        v6: Ipv6Net,
    ) -> Result<()> {
        if cfg!(windows) {
            win::run_with_retry(
                self.executor.as_ref(),
                &win::ipv4_address_args(tun_name, v4),
            )
            .await?;
            win::run(
                self.executor.as_ref(),
                &win::ipv6_address_args(tun_name, v6),
            )
            .await?;
            return win::run(self.executor.as_ref(), &win::mtu_args(tun_name, mtu)).await;
        }
        self.run_checked(
            "ip",
            &strings(&[
                "link",
                "set",
                "dev",
                tun_name,
                "mtu",
                &mtu.to_string(),
                "up",
            ]),
        )
        .await?;
        self.run_checked(
            "ip",
            &strings(&["addr", "replace", &v4.to_string(), "dev", tun_name]),
        )
        .await?;
        let mut args = vec!["-6".to_string()];
        args.extend(strings(&[
            "addr",
            "replace",
            &v6.to_string(),
            "dev",
            tun_name,
        ]));
        self.run_checked("ip", &args).await?;
        Ok(())
    }

    pub async fn set_link_mtu(&self, tun_name: &str, mtu: u16) -> Result<()> {
        if cfg!(windows) {
            return win::run(self.executor.as_ref(), &win::mtu_args(tun_name, mtu)).await;
        }
        self.run_checked(
            "ip",
            &strings(&["link", "set", "dev", tun_name, "mtu", &mtu.to_string()]),
        )
        .await
    }

    pub async fn apply_server(&self, plan: &ServerPlan) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        self.write_state(&AppliedState {
            mode: AppliedMode::Server,
            tun_name: plan.tun_name.clone(),
            table_id: 0,
            mark: 0,
            kill_switch: false,
        })?;
        let ruleset = server_nft(
            &plan.tun_name,
            &plan.v4.to_string(),
            &plan.v6.to_string(),
            plan.udp_port,
            plan.handshake_rate,
        );
        let host_v4 = Ipv4Net::new(plan.v4_address, plan.v4.prefix_len())
            .map_err(|error| RoutingError::Config(error.to_string()))?;
        let host_v6 = Ipv6Net::new(plan.v6_address, plan.v6.prefix_len())
            .map_err(|error| RoutingError::Config(error.to_string()))?;
        let result = async {
            self.apply_ruleset("rtun_srv", &ruleset).await?;
            self.configure_interface(&plan.tun_name, plan.mtu, host_v4, host_v6)
                .await
        }
        .await;
        if result.is_err() {
            let _ = self
                .executor
                .run("nft", &strings(&["delete", "table", "inet", "rtun_srv"]))
                .await;
            let _ = std::fs::remove_file(&self.state_path);
        }
        result
    }

    pub async fn cleanup_server(&self) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        let _ = self
            .executor
            .run("nft", &strings(&["delete", "table", "inet", "rtun_srv"]))
            .await;
        let _ = std::fs::remove_file(&self.state_path);
        Ok(())
    }

    pub async fn apply_kill_switch(&self, plan: &ClientPlan) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        if cfg!(windows) {
            if plan.kill_switch {
                tracing::warn!("kill switch is not implemented on Windows yet; traffic can leak while the tunnel is down");
            }
            return Ok(());
        }
        if plan.kill_switch {
            self.apply_ruleset("rtun_ks", &kill_switch_nft(plan))
                .await?;
        }
        Ok(())
    }

    pub async fn apply_client_routing(&self, plan: &ClientPlan) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        self.write_state(&AppliedState {
            mode: AppliedMode::Client,
            tun_name: plan.tun_name.clone(),
            table_id: plan.table_id,
            mark: plan.mark,
            kill_switch: plan.kill_switch,
        })?;
        if cfg!(windows) {
            return Ok(());
        }
        let result = async {
            self.apply_ruleset("rtun", &client_nft(plan)).await?;
            self.ip("ip", &client_ip_commands(plan)).await?;
            self.ip("ip -6", &client_ip6_commands(plan)).await
        }
        .await;
        if result.is_err() {
            self.cleanup_client_inner(plan).await;
            let _ = std::fs::remove_file(&self.state_path);
        }
        result
    }

    pub async fn install_split_routes(
        &self,
        plan: &ClientPlan,
        dev: &str,
        gateway_v4: Option<std::net::Ipv4Addr>,
        gateway_v6: Option<std::net::Ipv6Addr>,
    ) -> Result<()> {
        if cfg!(windows) {
            return self.install_windows_routes(plan, dev, gateway_v4).await;
        }
        let routes = plan_direct_routes(plan, dev, gateway_v4, gateway_v6);
        self.install_route_batches(&routes, plan.table_id).await
    }

    /// `dev` is the physical adapter index on Windows and the interface name elsewhere.
    async fn install_windows_routes(
        &self,
        plan: &ClientPlan,
        dev: &str,
        gateway: Option<std::net::Ipv4Addr>,
    ) -> Result<()> {
        let index = dev
            .parse::<u32>()
            .map_err(|_| RoutingError::Config(format!("invalid adapter index {dev}")))?;
        let physical = PhysicalRoute { index, gateway };
        let mut added = Vec::new();
        for route in win::route_plan(plan, &physical) {
            match win::run(self.executor.as_ref(), &win::route_args("add", &route)).await {
                Ok(()) => added.push(route),
                Err(error) if win::is_tunnel_half(&route) => {
                    *self.win_routes.lock().await = added.clone();
                    self.remove_windows_routes().await;
                    return Err(error);
                }
                Err(error) => {
                    tracing::warn!(%error, net = %route.net, "cannot add route");
                }
            }
        }
        *self.win_routes.lock().await = added;
        Ok(())
    }

    async fn remove_windows_routes(&self) {
        let routes = std::mem::take(&mut *self.win_routes.lock().await);
        for route in routes.iter().rev() {
            let _ = win::run(self.executor.as_ref(), &win::route_args("delete", route)).await;
        }
    }

    async fn install_route_batches(&self, routes: &[DirectRoute], table_id: u32) -> Result<()> {
        let v4 = routes
            .iter()
            .filter(|route| route.net.addr().is_ipv4())
            .cloned()
            .collect::<Vec<_>>();
        let v6 = routes
            .iter()
            .filter(|route| route.net.addr().is_ipv6())
            .cloned()
            .collect::<Vec<_>>();
        std::fs::create_dir_all(&self.run_dir)?;
        if !v4.is_empty() {
            self.run_route_batch("-4", &route_batch_lines(&v4, table_id))
                .await?;
        }
        if !v6.is_empty() {
            self.run_route_batch("-6", &route_batch_lines(&v6, table_id))
                .await?;
        }
        Ok(())
    }

    async fn run_route_batch(&self, family: &str, content: &str) -> Result<()> {
        let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = self.run_dir.join(format!(
            "rtun-routes-{}-{}.batch",
            std::process::id(),
            counter
        ));
        std::fs::write(&path, content)?;
        let args = vec![
            family.to_string(),
            "-batch".to_string(),
            path.to_string_lossy().to_string(),
        ];
        let result = self.run_checked("ip", &args).await;
        let _ = std::fs::remove_file(&path);
        result
    }

    pub async fn add_dynamic_direct_routes(
        &self,
        nets: &[ipnet::IpNet],
        dev: &str,
        gateway_v4: Option<std::net::Ipv4Addr>,
        gateway_v6: Option<std::net::Ipv6Addr>,
        table_id: u32,
    ) -> Result<()> {
        let mut routes = Vec::new();
        for net in nets {
            let link_local = match net.addr() {
                std::net::IpAddr::V4(ip) => ip.is_link_local(),
                std::net::IpAddr::V6(ip) => ip.octets()[0] == 0xfe && ip.octets()[1] & 0xc0 == 0x80,
            };
            let via = if link_local {
                None
            } else {
                match net.addr() {
                    std::net::IpAddr::V4(_) => gateway_v4.map(std::net::IpAddr::V4),
                    std::net::IpAddr::V6(_) => gateway_v6.map(std::net::IpAddr::V6),
                }
            };
            if !link_local && via.is_none() {
                continue;
            }
            routes.push(DirectRoute {
                net: *net,
                via,
                dev: dev.to_string(),
            });
        }
        self.install_route_batches(&routes, table_id).await
    }

    pub async fn add_dynamic_override_routes(
        &self,
        nets: &[ipnet::IpNet],
        tun: &str,
        table_id: u32,
    ) -> Result<()> {
        let routes = nets
            .iter()
            .map(|net| DirectRoute {
                net: *net,
                via: None,
                dev: tun.to_string(),
            })
            .collect::<Vec<_>>();
        self.install_route_batches(&routes, table_id).await
    }

    pub async fn add_override(
        &self,
        v4: &[ipnet::IpNet],
        v6: &[ipnet::IpNet],
        ttl_secs: Option<u64>,
    ) -> Result<()> {
        self.add_elements("dns_override4", "dns_override6", v4, v6, ttl_secs)
            .await
    }

    pub async fn add_direct(
        &self,
        v4: &[ipnet::IpNet],
        v6: &[ipnet::IpNet],
        ttl_secs: Option<u64>,
    ) -> Result<()> {
        self.add_elements("dns_direct4", "dns_direct6", v4, v6, ttl_secs)
            .await
    }

    async fn add_elements(
        &self,
        set4: &str,
        set6: &str,
        v4: &[ipnet::IpNet],
        v6: &[ipnet::IpNet],
        ttl_secs: Option<u64>,
    ) -> Result<()> {
        if !v4.is_empty() {
            let command = set_add_command("rtun", set4, v4, ttl_secs);
            let args = command
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            self.run_checked("nft", &args).await?;
        }
        if !v6.is_empty() {
            let command = set_add_command("rtun", set6, v6, ttl_secs);
            let args = command
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            self.run_checked("nft", &args).await?;
        }
        Ok(())
    }

    pub async fn apply_server_sysctls(&self) -> Result<()> {
        let settings = [
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
            ("net.ipv4.conf.all.rp_filter", "2"),
            ("net.ipv4.conf.default.rp_filter", "2"),
            ("net.ipv4.conf.all.send_redirects", "0"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv6.conf.all.accept_redirects", "0"),
        ];
        for (key, value) in settings {
            if let Err(error) = self
                .run_checked("sysctl", &strings(&["-w", &format!("{key}={value}")]))
                .await
            {
                tracing::warn!(%error, key, "cannot apply sysctl");
            }
        }
        Ok(())
    }

    pub fn state(&self) -> Result<Option<AppliedState>> {
        if !self.state_path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&self.state_path)?;
        Ok(Some(serde_json::from_str(&text)?))
    }

    fn write_state(&self, state: &AppliedState) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(state)?;
        let tmp = self.state_path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.state_path)?;
        Ok(())
    }

    async fn apply_ruleset(&self, table: &str, content: &str) -> Result<()> {
        let _ = table;
        std::fs::create_dir_all(&self.run_dir)?;
        let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = self
            .run_dir
            .join(format!("rtun-{}-{}.nft", std::process::id(), counter));
        std::fs::write(&path, content)?;
        let result = self
            .run_checked("nft", &strings(&["-f", &path.to_string_lossy()]))
            .await;
        let _ = std::fs::remove_file(&path);
        result
    }

    async fn ip(&self, program: &str, commands: &[Vec<String>]) -> Result<()> {
        let mut all = Vec::new();
        for command in commands {
            all.push(command.clone());
        }
        for command in all {
            self.run_checked(program, &command).await?;
        }
        Ok(())
    }

    async fn run_checked(&self, program: &str, args: &[String]) -> Result<()> {
        let (binary, prefix) = split_program(program);
        let mut full = prefix;
        full.extend_from_slice(args);
        let output = self.executor.run(binary, &full).await?;
        if output.status != 0 {
            return Err(RoutingError::Command {
                program: program.to_string(),
                args: full,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

fn split_program(program: &str) -> (&str, Vec<String>) {
    if let Some(rest) = program.strip_prefix("ip ") {
        ("ip", strings(&[rest]))
    } else {
        (program, Vec::new())
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        rulesets: Mutex<HashMap<String, String>>,
        fail_program: Option<String>,
        fail_args: Option<String>,
    }

    impl MockExecutor {
        #[allow(dead_code)]
        fn failing(program: &str, args: &str) -> Self {
            Self {
                fail_program: Some(program.into()),
                fail_args: Some(args.into()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl CommandExecutor for MockExecutor {
        async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
            self.calls
                .lock()
                .await
                .push((program.to_string(), args.to_vec()));
            if program == "nft" && args.len() == 2 && args[0] == "-f" {
                if let Ok(content) = std::fs::read_to_string(&args[1]) {
                    self.rulesets.lock().await.insert(args[1].clone(), content);
                }
            }
            let failed = self.fail_program.as_deref() == Some(program)
                && args
                    .iter()
                    .any(|arg| Some(arg.as_str()) == self.fail_args.as_deref());
            Ok(CommandOutput {
                status: if failed { 1 } else { 0 },
                stdout: Vec::new(),
                stderr: if failed {
                    b"mock failure".to_vec()
                } else {
                    Vec::new()
                },
            })
        }
    }

    fn plan() -> ClientPlan {
        crate::nft::build_client_plan(
            "rtun0",
            1360,
            1,
            51820,
            Vec::new(),
            Vec::new(),
            &["8.8.8.8".parse().unwrap()],
            &Default::default(),
            "10.66.0.0/24".parse().unwrap(),
            "fd66:1::/64".parse().unwrap(),
            &[],
            true,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn applies_nft_and_ip_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager.apply_client(&plan()).await.unwrap();
        let calls = mock.calls.lock().await;
        assert!(calls.iter().any(|(program, _)| program == "nft"));
        assert!(calls
            .iter()
            .any(|(program, args)| program == "ip" && args.contains(&"fwmark".to_string())));
        assert!(calls.iter().any(
            |(program, args)| program == "ip" && args.first().map(String::as_str) == Some("-6")
        ));
        let rulesets = mock.rulesets.lock().await;
        assert!(rulesets
            .values()
            .any(|content| content.contains("table inet rtun_ks")));
        assert!(manager.state().unwrap().is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failure_rolls_back_and_clears_state() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::failing("ip", "route"));
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        assert!(manager.apply_client(&plan()).await.is_err());
        assert!(manager.state().unwrap().is_none());
        let calls = mock.calls.lock().await;
        assert!(calls
            .iter()
            .any(|(program, args)| program == "nft"
                && args.join(" ").contains("delete table inet rtun")));
    }

    #[tokio::test]
    async fn recovery_cleans_known_tables() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        std::fs::write(
            dir.path().join("state.json"),
            r#"{"mode":"client","tun_name":"rtun0","table_id":51820,"mark":1,"kill_switch":true}"#,
        )
        .unwrap();
        manager.recover().await.unwrap();
        assert!(manager.state().unwrap().is_none());
        let calls = mock.calls.lock().await;
        assert!(calls
            .iter()
            .any(|(_, args)| args.join(" ").contains("delete table inet rtun_ks")));
    }

    #[tokio::test]
    async fn server_plan_applies_nat_and_interface() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager
            .apply_server(&ServerPlan {
                tun_name: "rtun0".into(),
                mtu: 1360,
                v4: "10.66.0.0/24".parse().unwrap(),
                v6: "fd66:1::/64".parse().unwrap(),
                v4_address: "10.66.0.1".parse().unwrap(),
                v6_address: "fd66:1::1".parse().unwrap(),
                udp_port: 443,
                handshake_rate: 50,
            })
            .await
            .unwrap();
        let rulesets = mock.rulesets.lock().await;
        assert!(rulesets
            .values()
            .any(|content| content.contains("masquerade")));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_routes_are_installed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager
            .install_split_routes(&plan(), "7", Some("192.168.1.1".parse().unwrap()), None)
            .await
            .unwrap();
        manager.cleanup_client(&plan()).await.unwrap();
        let calls = mock.calls.lock().await;
        let netsh = |action: &str| {
            calls.iter().any(|(program, args)| {
                program == "netsh"
                    && args.contains(&action.to_string())
                    && args.contains(&"prefix=0.0.0.0/1".to_string())
            })
        };
        assert!(netsh("add"));
        assert!(netsh("delete"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installs_split_route_batches() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager
            .install_split_routes(
                &plan(),
                "eth0",
                Some("10.0.0.1".parse().unwrap()),
                Some("2001:db8::1".parse().unwrap()),
            )
            .await
            .unwrap();
        let calls = mock.calls.lock().await;
        assert!(calls.iter().any(|(program, args)| program == "ip"
            && args.first().map(String::as_str) == Some("-4")
            && args.get(1).map(String::as_str) == Some("-batch")));
        assert!(calls.iter().any(|(program, args)| program == "ip"
            && args.first().map(String::as_str) == Some("-6")
            && args.get(1).map(String::as_str) == Some("-batch")));
    }

    #[tokio::test]
    async fn dns_updates_use_dynamic_sets() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager
            .add_direct(&["1.2.3.0/24".parse().unwrap()], &[], Some(300))
            .await
            .unwrap();
        manager
            .add_override(&["5.6.7.0/24".parse().unwrap()], &[], Some(300))
            .await
            .unwrap();
        let calls = mock.calls.lock().await;
        assert!(calls
            .iter()
            .any(|(_, args)| args.iter().any(|arg| arg == "dns_direct4")));
        assert!(calls
            .iter()
            .any(|(_, args)| args.iter().any(|arg| arg == "dns_override4")));
    }

    #[tokio::test]
    async fn sysctls_are_applied() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockExecutor::default());
        let manager = RuleManager::new(
            mock.clone(),
            dir.path().join("state.json"),
            dir.path().join("run"),
        );
        manager.apply_server_sysctls().await.unwrap();
        let calls = mock.calls.lock().await;
        assert_eq!(
            calls
                .iter()
                .filter(|(program, _)| program == "sysctl")
                .count(),
            7
        );
    }
}
