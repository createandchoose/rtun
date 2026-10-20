use ksni::menu::{MenuItem, StandardItem};
use ksni::{Tray, TrayMethods};
use rt_clientd::Status;
use slint::{ComponentHandle, Weak};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

slint::include_modules!();

#[derive(Debug, Clone)]
enum Command {
    Connect,
    Disconnect,
    SetTransport(String),
    SetKillSwitch(bool),
    Quit,
}

struct TrayState {
    tx: UnboundedSender<Command>,
    summary: String,
}

impl Tray for TrayState {
    fn id(&self) -> String {
        "rtun".into()
    }

    fn title(&self) -> String {
        format!("RTUN — {}", self.summary)
    }

    fn icon_name(&self) -> String {
        "network-vpn".into()
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            MenuItem::Standard(StandardItem {
                label: "Подключиться".into(),
                activate: Box::new(|tray: &mut TrayState| {
                    let _ = tray.tx.send(Command::Connect);
                }),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Отключиться".into(),
                activate: Box::new(|tray: &mut TrayState| {
                    let _ = tray.tx.send(Command::Disconnect);
                }),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "UDP (obfs)".into(),
                activate: Box::new(|tray: &mut TrayState| {
                    let _ = tray.tx.send(Command::SetTransport("obfs-udp".into()));
                }),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "WSS (резерв)".into(),
                activate: Box::new(|tray: &mut TrayState| {
                    let _ = tray.tx.send(Command::SetTransport("ws-tls".into()));
                }),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Выход".into(),
                activate: Box::new(|tray: &mut TrayState| {
                    let _ = tray.tx.send(Command::Quit);
                }),
                ..Default::default()
            }),
        ]
    }
}

#[zbus::proxy(
    interface = "org.rtun.Client1",
    default_service = "org.rtun.Client1",
    default_path = "/org/rtun/Client1"
)]
trait Client1 {
    #[zbus(name = "Connect")]
    fn connect(&self) -> zbus::Result<()>;
    #[zbus(name = "Disconnect")]
    fn disconnect(&self) -> zbus::Result<()>;
    #[zbus(name = "Status")]
    fn status(&self) -> zbus::Result<String>;
    #[zbus(name = "SetTransport")]
    fn set_transport(&self, kind: &str) -> zbus::Result<()>;
    #[zbus(name = "SetKillSwitch")]
    fn set_kill_switch(&self, enabled: bool) -> zbus::Result<()>;
    #[zbus(name = "GetDiagnostics")]
    fn get_diagnostics(&self) -> zbus::Result<String>;
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    ui.set_kill_switch(true);
    ui.set_smart_routing(true);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let ui_connect = ui.as_weak();
    let connect_tx = tx.clone();
    ui.on_connect_clicked(move || {
        if let Some(ui) = ui_connect.upgrade() {
            ui.set_error_text("".into());
        }
        let _ = connect_tx.send(Command::Connect);
    });

    let ui_disconnect = ui.as_weak();
    let disconnect_tx = tx.clone();
    ui.on_disconnect_clicked(move || {
        if let Some(ui) = ui_disconnect.upgrade() {
            ui.set_error_text("".into());
        }
        let _ = disconnect_tx.send(Command::Disconnect);
    });

    let ui_udp = ui.as_weak();
    let udp_tx = tx.clone();
    ui.on_select_udp(move || {
        if let Some(ui) = ui_udp.upgrade() {
            ui.set_error_text("".into());
        }
        let _ = udp_tx.send(Command::SetTransport("obfs-udp".into()));
    });

    let ui_ws = ui.as_weak();
    let ws_tx = tx.clone();
    ui.on_select_ws(move || {
        if let Some(ui) = ui_ws.upgrade() {
            ui.set_error_text("".into());
        }
        let _ = ws_tx.send(Command::SetTransport("ws-tls".into()));
    });

    let ui_kill = ui.as_weak();
    let kill_tx = tx.clone();
    ui.on_kill_toggled(move |enabled| {
        if let Some(ui) = ui_kill.upgrade() {
            ui.set_kill_switch(enabled);
        }
        let _ = kill_tx.send(Command::SetKillSwitch(enabled));
    });

    let weak: Weak<AppWindow> = ui.as_weak();
    let tray_tx = tx.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("tokio runtime");
    std::thread::spawn(move || {
        runtime.block_on(control_loop(rx, weak, tray_tx));
    });

    ui.run()
}

async fn control_loop(
    mut rx: UnboundedReceiver<Command>,
    ui: Weak<AppWindow>,
    tray_tx: UnboundedSender<Command>,
) {
    let connection = match zbus::Connection::system().await {
        Ok(connection) => connection,
        Err(error) => {
            update_ui(
                &ui,
                None,
                Some(format!("Системная шина D-Bus недоступна: {error}")),
            );
            while let Some(command) = rx.recv().await {
                if matches!(command, Command::Quit) {
                    break;
                }
            }
            return;
        }
    };
    match Client1Proxy::new(&connection).await {
        Ok(proxy) => {
            let tray = TrayState {
                tx: tray_tx,
                summary: "нет соединения".into(),
            };
            let handle = tray.spawn().await.ok();
            poll(proxy, &mut rx, &ui, handle).await;
        }
        Err(error) => {
            update_ui(
                &ui,
                None,
                Some(format!(
                    "Демон недоступен через D-Bus: {error}. Запустите rt-clientd."
                )),
            );
            while let Some(command) = rx.recv().await {
                if matches!(command, Command::Quit) {
                    break;
                }
            }
        }
    }
}

async fn poll(
    proxy: Client1Proxy<'_>,
    rx: &mut UnboundedReceiver<Command>,
    ui: &Weak<AppWindow>,
    tray: Option<ksni::Handle<TrayState>>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            command = rx.recv() => {
                let Some(command) = command else { break; };
                let result = match command {
                    Command::Connect => proxy.connect().await,
                    Command::Disconnect => proxy.disconnect().await,
                    Command::SetTransport(kind) => proxy.set_transport(&kind).await,
                    Command::SetKillSwitch(enabled) => proxy.set_kill_switch(enabled).await,
                    Command::Quit => break,
                };
                if let Err(error) = result {
                    update_ui(ui, None, Some(format!("Ошибка D-Bus: {error}")));
                }
            }
            _ = ticker.tick() => {
                match proxy.status().await {
                    Ok(json) => match serde_json::from_str::<Status>(&json) {
                        Ok(status) => {
                            if let Some(handle) = &tray {
                                let summary = format!(
                                    "{}{}",
                                    status.state.as_str(),
                                    status.transport.map(|kind| format!(" · {kind}")).unwrap_or_default()
                                );
                                handle.update(|tray| tray.summary = summary).await;
                            }
                            update_ui(ui, Some(status), None);
                        }
                        Err(error) => update_ui(ui, None, Some(format!("Некорректный статус: {error}"))),
                    },
                    Err(error) => update_ui(ui, None, Some(format!("Демон недоступен: {error}"))),
                }
            }
        }
    }
}

fn update_ui(ui: &Weak<AppWindow>, status: Option<Status>, error: Option<String>) {
    let ui = ui.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(ui) = ui.upgrade() else {
            return;
        };
        if let Some(status) = status {
            ui.set_status_text(state_label(status.state).into());
            ui.set_endpoint_text(status.endpoint.unwrap_or_else(|| "—".into()).into());
            ui.set_transport_text(
                status
                    .transport
                    .map(|kind| kind.to_string())
                    .unwrap_or_else(|| "—".into())
                    .into(),
            );
            ui.set_rtt_text(
                status
                    .rtt_ms
                    .map(|rtt| format!("{rtt:.0} мс"))
                    .unwrap_or_else(|| "—".into())
                    .into(),
            );
            ui.set_traffic_text(
                format!(
                    "{} / {}",
                    format_bytes(status.tx_bytes),
                    format_bytes(status.rx_bytes)
                )
                .into(),
            );
            ui.set_dns_text(
                if !status.dns_active {
                    "выключен"
                } else if status.dns_degraded {
                    "degraded (GeoIP)"
                } else {
                    "split DNS"
                }
                .into(),
            );
            ui.set_kill_switch(status.kill_switch);
            if let Some(message) = status.last_error {
                ui.set_error_text(message.into());
            }
        }
        if let Some(error) = error {
            ui.set_error_text(error.into());
        }
    });
}

fn state_label(state: rt_clientd::ClientState) -> String {
    match state {
        rt_clientd::ClientState::Disconnected => "Отключено".into(),
        rt_clientd::ClientState::Resolving => "Поиск сервера".into(),
        rt_clientd::ClientState::Handshaking => "Handshake".into(),
        rt_clientd::ClientState::Connected => "Подключено".into(),
        rt_clientd::ClientState::Degraded => "Degraded".into(),
        rt_clientd::ClientState::Reconnecting => "Переподключение".into(),
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
