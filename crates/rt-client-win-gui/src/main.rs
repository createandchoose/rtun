//! Окно RTUN для Windows: подключение в один клик, понятный статус и журнал.
//! Туннель работает в фоновом рантайме. При закрытии окна туннель сначала
//! отключается и откатывает сетевые настройки, и только потом окно закрывается.

slint::include_modules!();

mod preferences_ui;
mod server_install;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rt_client_win::plan::load_config;
use rt_client_win::{explain, is_elevated, TunnelState};
use slint::{CloseRequestResponse, ComponentHandle, ModelRc, VecModel, Weak};
use tokio::runtime::{Handle, Runtime};
use tokio::sync::watch;

const LEVEL_INFO: i32 = 0;
const LEVEL_ERROR: i32 = 1;
const LEVEL_OK: i32 = 2;
const MAX_EVENTS: usize = 100;

#[derive(Default)]
struct AppState {
    preferences: rt_client_win::preferences::SmartPreferences,
    config_path: Option<PathBuf>,
    tunnel: TunnelState,
    elevated: bool,
    /// Есть, пока туннель запущен; отправка `true` инициирует отключение.
    stop: Option<watch::Sender<bool>>,
    /// Окно закрыто пользователем, пока туннель еще снимается.
    closing: bool,
    events: Vec<(String, i32)>,
    /// Установка сервера идет в фоне.
    deploying: bool,
    deploy_status: String,
}

type Shared = Arc<Mutex<AppState>>;

enum Action {
    None,
    Pick,
    Start(PathBuf),
}

fn push_event(state: &mut AppState, text: impl Into<String>, level: i32) {
    state.events.push((text.into(), level));
    if state.events.len() > MAX_EVENTS {
        state.events.remove(0);
    }
}

/// Записывает переход состояния в журнал и обновляет состояние.
fn apply_tunnel_state(state: &mut AppState, next: TunnelState) {
    match &next {
        TunnelState::Handshaking { endpoint } => {
            push_event(state, format!("Рукопожатие с {endpoint}"), LEVEL_INFO);
        }
        TunnelState::Connected { endpoint, .. } => {
            push_event(state, format!("Туннель поднят: {endpoint}"), LEVEL_OK);
        }
        TunnelState::Reconnecting { reason, .. } => {
            push_event(state, reason.clone(), LEVEL_ERROR);
        }
        _ => {}
    }
    state.tunnel = next;
}

/// Переносит состояние в элементы интерфейса. Вызывается только в UI-потоке.
fn render(ui: &MainWindow, state: &AppState) {
    preferences_ui::render(ui, &state.preferences);
    let mut endpoint = "—".to_string();
    let mut tunnel_ip = "—".to_string();
    let (kind, title, detail) = match &state.tunnel {
        TunnelState::Idle => {
            let detail = if state.config_path.is_some() {
                "Нажмите «Подключиться», чтобы защитить соединение."
            } else {
                "Выберите файл конфига, чтобы начать."
            };
            (0, "Не подключено".to_string(), detail.to_string())
        }
        TunnelState::Connecting => (
            1,
            "Подключаемся…".to_string(),
            "Проверяем связь с сервером.".to_string(),
        ),
        TunnelState::Handshaking { endpoint: server } => {
            endpoint = server.clone();
            (
                1,
                "Подключаемся…".to_string(),
                format!("Рукопожатие с {server}."),
            )
        }
        TunnelState::Connected {
            endpoint: server,
            tunnel_ip: ip,
            ..
        } => {
            endpoint = server.clone();
            tunnel_ip = ip.clone();
            (
                2,
                "Подключено".to_string(),
                "Трафик идёт через туннель.".to_string(),
            )
        }
        TunnelState::Reconnecting {
            reason,
            retry_in_secs,
        } => (
            3,
            "Переподключаемся…".to_string(),
            format!("{reason} Повтор через {retry_in_secs} с."),
        ),
        TunnelState::Stopping => (
            1,
            "Отключаем…".to_string(),
            "Возвращаем сетевые настройки.".to_string(),
        ),
    };

    let config_name = state
        .config_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Конфиг не выбран".to_string());

    ui.set_state_kind(kind);
    ui.set_state_title(title.into());
    ui.set_state_detail(detail.into());
    ui.set_endpoint(endpoint.into());
    if let TunnelState::Connected { endpoint, .. } = &state.tunnel {
        if let Some((_, transport)) = endpoint.rsplit_once(" · ") {
            ui.set_transport_caption(transport.into());
        }
    }
    ui.set_tunnel_ip(tunnel_ip.into());
    ui.set_config_name(config_name.into());
    ui.set_has_config(state.config_path.is_some());
    ui.set_busy(matches!(state.tunnel, TunnelState::Stopping));
    ui.set_elevated(state.elevated);
    ui.set_deploy_busy(state.deploying);
    ui.set_deploy_status(state.deploy_status.clone().into());
    if !matches!(state.tunnel, TunnelState::Connected { .. }) {
        ui.set_uptime("—".into());
    }
    let items: Vec<EventItem> = state
        .events
        .iter()
        .map(|(text, level)| EventItem {
            text: text.into(),
            level: *level,
        })
        .collect();
    ui.set_events(ModelRc::new(VecModel::from(items)));
}

/// Меняет состояние из фонового потока и перерисовывает окно в UI-потоке.
fn update_from_thread<F>(ui: &Weak<MainWindow>, shared: &Shared, update: F)
where
    F: FnOnce(&mut AppState) + Send + 'static,
{
    let ui = ui.clone();
    let shared = Arc::clone(shared);
    let _ = slint::invoke_from_event_loop(move || {
        let mut state = shared.lock().unwrap();
        update(&mut state);
        if let Some(ui) = ui.upgrade() {
            render(&ui, &state);
        }
    });
}

fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        total / 3600,
        (total / 60) % 60,
        total % 60
    )
}

fn settings_file() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("rtun").join("gui.json"))
}

fn load_last_config() -> Option<PathBuf> {
    let text = std::fs::read_to_string(settings_file()?).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let path = PathBuf::from(value.get("config")?.as_str()?);
    path.is_file().then_some(path)
}

fn save_last_config(path: &Path) {
    let Some(file) = settings_file() else {
        return;
    };
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = serde_json::json!({ "config": path.display().to_string() });
    let _ = std::fs::write(file, body.to_string());
}

fn pick_config(ui: &MainWindow, shared: &Shared) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Конфиг RTUN", &["conf", "toml"])
        .pick_file()
    else {
        return;
    };
    save_last_config(&path);
    let mut state = shared.lock().unwrap();
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    state.config_path = Some(path);
    push_event(&mut state, format!("Выбран конфиг: {name}"), LEVEL_INFO);
    render(ui, &state);
}

fn start(handle: &Handle, ui_weak: &Weak<MainWindow>, shared: &Shared, path: PathBuf) {
    let config = match load_config(&path) {
        Ok(config) => config,
        Err(error) => {
            let mut state = shared.lock().unwrap();
            push_event(&mut state, explain(&error), LEVEL_ERROR);
            if let Some(ui) = ui_weak.upgrade() {
                render(&ui, &state);
            }
            return;
        }
    };
    let preferences = shared.lock().unwrap().preferences.clone();

    let (stop_tx, stop_rx) = watch::channel(false);
    let (status_tx, status_rx) = watch::channel(TunnelState::Connecting);
    {
        let mut state = shared.lock().unwrap();
        state.stop = Some(stop_tx);
        state.tunnel = TunnelState::Connecting;
        push_event(
            &mut state,
            format!(
                "Подключаемся к {}:{}",
                config.endpoint.host, config.endpoint.port
            ),
            LEVEL_INFO,
        );
        if let Some(ui) = ui_weak.upgrade() {
            render(&ui, &state);
        }
    }

    // Передаем состояния из фонового потока в UI.
    let ui_forward = ui_weak.clone();
    let shared_forward = Arc::clone(shared);
    handle.spawn(async move {
        let mut status_rx = status_rx;
        loop {
            let next = status_rx.borrow_and_update().clone();
            let ui = ui_forward.clone();
            let shared = Arc::clone(&shared_forward);
            let _ = slint::invoke_from_event_loop(move || {
                let mut state = shared.lock().unwrap();
                apply_tunnel_state(&mut state, next);
                if let Some(ui) = ui.upgrade() {
                    render(&ui, &state);
                }
            });
            if status_rx.changed().await.is_err() {
                break;
            }
        }
    });

    // Сам туннель. По завершении снимаем состояние и, если окно закрыто, выходим.
    let ui_done = ui_weak.clone();
    let shared_done = Arc::clone(shared);
    handle.spawn(async move {
        let result =
            rt_client_win::smart_engine::run(config, preferences, stop_rx, status_tx).await;
        let _ = slint::invoke_from_event_loop(move || {
            let mut state = shared_done.lock().unwrap();
            state.stop = None;
            state.tunnel = TunnelState::Idle;
            match result {
                Ok(()) => push_event(
                    &mut state,
                    "Отключено. Сетевые настройки восстановлены.",
                    LEVEL_INFO,
                ),
                Err(error) => push_event(&mut state, explain(&error), LEVEL_ERROR),
            }
            if let Some(ui) = ui_done.upgrade() {
                render(&ui, &state);
            }
            if state.closing {
                let _ = slint::quit_event_loop();
            }
        });
    });
}

/// Перезапускает программу с правами администратора (UAC).
fn relaunch_elevated() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let quoted = exe.display().to_string().replace('\'', "''");
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &format!("Start-Process -FilePath '{quoted}' -Verb RunAs"),
        ])
        .spawn()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let runtime = Runtime::new()?;
    let handle = runtime.handle().clone();
    let ui = MainWindow::new()?;

    let preferences = rt_client_win::preferences::SmartPreferences::load();
    let preferences_error = preferences.as_ref().err().cloned();
    let shared: Shared = Arc::new(Mutex::new(AppState {
        preferences: preferences.unwrap_or_default(),
        config_path: load_last_config(),
        elevated: is_elevated(),
        ..Default::default()
    }));
    preferences_ui::bind(&ui, &shared, &handle);
    {
        let mut state = shared.lock().unwrap();
        if let Some(error) = preferences_error {
            push_event(
                &mut state,
                format!("Не удалось прочитать правила фильтрации: {error}"),
                LEVEL_ERROR,
            );
        }
        if !state.elevated {
            push_event(
                &mut state,
                "Программа запущена без прав администратора.",
                LEVEL_ERROR,
            );
        }
        push_event(&mut state, "Готово к работе.", LEVEL_INFO);
        render(&ui, &state);
    }

    ui.on_pick_config({
        let ui = ui.as_weak();
        let shared = Arc::clone(&shared);
        move || {
            if let Some(ui) = ui.upgrade() {
                pick_config(&ui, &shared);
            }
        }
    });

    ui.on_toggle_connection({
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        let handle = handle.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let action = {
                let mut state = shared.lock().unwrap();
                if state.stop.is_some() {
                    if let Some(stop) = state.stop.as_ref() {
                        let _ = stop.send(true);
                    }
                    state.tunnel = TunnelState::Stopping;
                    push_event(&mut state, "Отключаемся…", LEVEL_INFO);
                    render(&ui, &state);
                    Action::None
                } else if let Some(path) = state.config_path.clone() {
                    if state.elevated {
                        Action::Start(path)
                    } else {
                        push_event(
                            &mut state,
                            "Нужны права администратора. Нажмите «Перезапустить».",
                            LEVEL_ERROR,
                        );
                        render(&ui, &state);
                        Action::None
                    }
                } else {
                    Action::Pick
                }
            };
            match action {
                Action::None => {}
                Action::Pick => pick_config(&ui, &shared),
                Action::Start(path) => start(&handle, &ui_weak, &shared, path),
            }
        }
    });

    ui.on_relaunch_admin({
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut state = shared.lock().unwrap();
            if state.stop.is_some() {
                push_event(
                    &mut state,
                    "Сначала отключите туннель, затем перезапустите программу.",
                    LEVEL_ERROR,
                );
                render(&ui, &state);
                return;
            }
            match relaunch_elevated() {
                // Новый экземпляр уже запрашивает UAC; текущий закрываем.
                Ok(()) => {
                    let _ = slint::quit_event_loop();
                }
                Err(error) => {
                    push_event(
                        &mut state,
                        format!("Не удалось перезапустить: {error}"),
                        LEVEL_ERROR,
                    );
                    render(&ui, &state);
                }
            }
        }
    });

    // Закрытие окна при активном туннеле: сначала откат, потом выход.
    ui.window().on_close_requested({
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        move || {
            let mut state = shared.lock().unwrap();
            if state.stop.is_none() {
                return CloseRequestResponse::HideWindow;
            }
            state.closing = true;
            if let Some(stop) = state.stop.as_ref() {
                let _ = stop.send(true);
            }
            state.tunnel = TunnelState::Stopping;
            push_event(&mut state, "Отключаемся перед выходом…", LEVEL_INFO);
            if let Some(ui) = ui_weak.upgrade() {
                render(&ui, &state);
            }
            CloseRequestResponse::KeepWindowShown
        }
    });

    // Счетчик времени работы обновляется раз в секунду.
    let uptime_timer = slint::Timer::default();
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        uptime_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(1),
            move || {
                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                let state = shared.lock().unwrap();
                if let TunnelState::Connected { since, .. } = state.tunnel {
                    ui.set_uptime(format_duration(since.elapsed()).into());
                }
            },
        );
    }

    ui.on_pick_key({
        let ui = ui.as_weak();
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                ui.set_srv_key(path.display().to_string().into());
                ui.set_srv_use_key(true);
            }
        }
    });

    ui.on_deploy_start({
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        let handle = handle.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let credentials = if ui.get_srv_use_key() {
                server_install::Credentials::KeyFile(PathBuf::from(ui.get_srv_key().to_string()))
            } else {
                server_install::Credentials::Password(ui.get_srv_password().to_string())
            };
            // Пароль не держим в интерфейсе дольше, чем нужно для запуска.
            ui.set_srv_password("".into());
            let form = server_install::ServerForm {
                host: ui.get_srv_host().to_string(),
                user: ui.get_srv_user().to_string(),
                credentials,
                domain: ui.get_srv_domain().to_string(),
                email: ui.get_srv_email().to_string(),
                peer: ui.get_srv_peer().to_string(),
            };
            server_install::start(&handle, &ui_weak, &shared, form);
        }
    });

    #[cfg(debug_assertions)]
    if let Some(output) = std::env::var_os("RTUN_PREVIEW_OUTPUT") {
        preferences_ui::preview(&ui, &runtime, PathBuf::from(output));
    }
    ui.run()?;
    drop(uptime_timer);
    drop(runtime);
    Ok(())
}
