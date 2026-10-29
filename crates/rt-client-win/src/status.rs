//! Состояние туннеля для интерфейса и понятные тексты ошибок.

use std::time::Instant;

use crate::error::ClientWinError;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum TunnelState {
    #[default]
    Idle,
    Connecting,
    Handshaking {
        endpoint: String,
    },
    Connected {
        endpoint: String,
        tunnel_ip: String,
        since: Instant,
    },
    Reconnecting {
        reason: String,
        retry_in_secs: u64,
    },
    Stopping,
}

/// Текст для пользователя вместо технической ошибки.
pub fn explain(error: &ClientWinError) -> String {
    match error {
        ClientWinError::Handshake(_) => {
            "Сервер не отвечает. Проверьте адрес сервера и что порт 443 (UDP) открыт.".into()
        }
        ClientWinError::NoPhysicalRoute => {
            "Не найден обычный сетевой адаптер. Проверьте подключение к интернету.".into()
        }
        ClientWinError::Routing(_) => {
            "Не удалось настроить сеть Windows. Запустите RTUN от имени администратора.".into()
        }
        ClientWinError::Tunnel(_) => {
            "Не удалось создать туннельный адаптер. Проверьте wintun.dll рядом с программой и права администратора.".into()
        }
        ClientWinError::Config(message) => format!("Ошибка в конфиге: {message}"),
        ClientWinError::Transport(_) => "Ошибка сети при обмене с сервером.".into(),
        ClientWinError::Io(error) => format!("Ошибка ввода-вывода: {error}"),
    }
}

/// Запущен ли процесс с правами администратора.
///
/// Проверяем уровень целостности: у процесса от администратора это SID
/// `S-1-16-12288`. Имя группы «Administrators» не подходит: на русской Windows
/// группа называется иначе, и проверка давала бы ложный отказ.
pub fn is_elevated() -> bool {
    std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("S-1-16-12288"))
        .unwrap_or(false)
}
