//! Установка сервера RTUN на VPS прямо из окна, в духе AmneziaVPN: данные
//! сервера и SSH-доступ, дальше программа сама ставит сервер, сохраняет
//! клиентский конфиг и выбирает его для подключения. Пароль в память
//! не сохраняется и на диск не пишется.

use std::path::PathBuf;
use std::sync::Arc;

use rt_deploy::pipeline::{self, DeployPlan, Step};
use rt_deploy::{RusshRemote, SshAuth, VpsTarget};
use slint::Weak;
use tokio::runtime::Handle;

use crate::{
    push_event, render, save_last_config, update_from_thread, MainWindow, Shared, LEVEL_ERROR,
    LEVEL_INFO, LEVEL_OK,
};

pub enum Credentials {
    Password(String),
    KeyFile(PathBuf),
}

pub struct ServerForm {
    pub host: String,
    pub user: String,
    pub credentials: Credentials,
    pub domain: String,
    pub email: String,
    pub peer: String,
}

/// Запускает установку в фоне. Проверки, которые можно сделать сразу,
/// выполняются здесь же и сообщаются в журнал.
pub fn start(handle: &Handle, ui: &Weak<MainWindow>, shared: &Shared, form: ServerForm) {
    let mut state = shared.lock().unwrap();
    if state.deploying {
        return;
    }
    let problem = if form.host.trim().is_empty() {
        Some("Укажите адрес сервера.".to_string())
    } else if form.domain.trim().is_empty() {
        Some("Укажите домен, который указывает на сервер.".to_string())
    } else if matches!(&form.credentials, Credentials::Password(p) if p.is_empty()) {
        Some("Введите пароль от сервера.".to_string())
    } else if matches!(&form.credentials, Credentials::KeyFile(p) if p.as_os_str().is_empty()) {
        Some("Выберите файл приватного ключа.".to_string())
    } else {
        None
    };
    let repo_root = find_repo_root();
    let problem = problem.or_else(|| match &repo_root {
        None => Some(
            "Не найдены файлы сервера (packaging/server). Запустите программу из папки репозитория RTUN."
                .to_string(),
        ),
        Some(root) if !root.join("target/release/rtund").is_file() => Some(
            "Не найден собранный сервер (target/release/rtund). Соберите его по docs/deploy.md."
                .to_string(),
        ),
        Some(_) => None,
    });
    if let Some(message) = problem {
        push_event(&mut state, message, LEVEL_ERROR);
        if let Some(ui) = ui.upgrade() {
            render(&ui, &state);
        }
        return;
    }

    let plan = DeployPlan {
        repo_root: repo_root.unwrap_or_default(),
        domain: form.domain.trim().to_string(),
        email: form.email.trim().to_string(),
        peer_name: form.peer.trim().to_string(),
        peer_index: 2,
    };
    if let Err(error) = pipeline::validate_plan(&plan) {
        push_event(&mut state, error.to_string(), LEVEL_ERROR);
        if let Some(ui) = ui.upgrade() {
            render(&ui, &state);
        }
        return;
    }

    state.deploying = true;
    state.deploy_status = "Подключаемся к серверу…".to_string();
    push_event(
        &mut state,
        format!("Установка сервера на {}", form.host.trim()),
        LEVEL_INFO,
    );
    if let Some(ui) = ui.upgrade() {
        render(&ui, &state);
    }
    drop(state);

    let target = VpsTarget {
        host: form.host.trim().to_string(),
        port: 22,
        user: form.user.trim().to_string(),
    };
    let auth = match form.credentials {
        Credentials::Password(password) => SshAuth::Password(password),
        Credentials::KeyFile(path) => SshAuth::KeyFile(path),
    };
    let ui = ui.clone();
    let shared = Arc::clone(shared);
    handle.spawn(async move {
        deploy(target, auth, plan, ui, shared).await;
    });
}

async fn deploy(
    target: VpsTarget,
    auth: SshAuth,
    plan: DeployPlan,
    ui: Weak<MainWindow>,
    shared: Shared,
) {
    let mut remote = match RusshRemote::connect(&target, &auth).await {
        Ok(remote) => remote,
        Err(error) => {
            finish(
                &ui,
                &shared,
                Err(format!("Не удалось подключиться к серверу: {error}")),
            );
            return;
        }
    };

    let progress_ui = ui.clone();
    let progress_shared = Arc::clone(&shared);
    let mut progress = |step: Step| {
        let line = format!("Шаг: {}", step.label());
        let line_for_status = line.clone();
        update_from_thread(&progress_ui, &progress_shared, move |state| {
            state.deploy_status = line_for_status;
            push_event(state, line, LEVEL_INFO);
        });
    };
    let outcome = pipeline::deploy(&plan, &mut remote, &mut progress).await;
    let _ = remote.close().await;

    match outcome {
        Ok(result) => {
            let path = config_dir().join(format!("rtun-{}.conf", result.peer_name));
            match result.client_conf.save(&path) {
                Ok(()) => finish(&ui, &shared, Ok(path)),
                Err(error) => finish(
                    &ui,
                    &shared,
                    Err(format!("Сервер установлен, но конфиг не сохранен: {error}")),
                ),
            }
        }
        Err(error) => finish(&ui, &shared, Err(error.to_string())),
    }
}

fn finish(ui: &Weak<MainWindow>, shared: &Shared, result: Result<PathBuf, String>) {
    update_from_thread(ui, shared, move |state| {
        state.deploying = false;
        state.deploy_status = String::new();
        match result {
            Ok(path) => {
                save_last_config(&path);
                push_event(
                    state,
                    format!("Сервер установлен. Конфиг сохранен: {}", path.display()),
                    LEVEL_OK,
                );
                push_event(
                    state,
                    "Перейдите в «Подключение» и нажмите «Подключиться».",
                    LEVEL_INFO,
                );
                state.config_path = Some(path);
            }
            Err(message) => push_event(state, message, LEVEL_ERROR),
        }
    });
}

/// Папка репозитория: ищем `packaging/server/install.sh` вверх от exe.
fn find_repo_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        if dir
            .join("packaging")
            .join("server")
            .join("install.sh")
            .is_file()
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn config_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(|dir| PathBuf::from(dir).join("rtun"))
        .unwrap_or_else(|| PathBuf::from(".").join("rtun"))
}
