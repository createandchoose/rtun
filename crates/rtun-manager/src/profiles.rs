//! Профили VPS. Пароли сюда не пишутся: только путь к ключу, если он нужен.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vps {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub user: String,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

fn default_port() -> u16 {
    22
}

fn default_user() -> String {
    "root".into()
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profiles {
    #[serde(default, rename = "vps")]
    pub vps: Vec<Vps>,
}

impl Profiles {
    /// Отсутствующий файл — пустой список профилей.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|error| format!("cannot parse {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string_pretty(self).map_err(|error| error.to_string())?;
        rt_proto::config::write_secure(path, text.as_bytes()).map_err(|error| error.to_string())
    }

    pub fn find(&self, name: &str) -> Option<&Vps> {
        self.vps.iter().find(|vps| vps.name == name)
    }

    pub fn add(&mut self, vps: Vps) -> Result<(), String> {
        if self.find(&vps.name).is_some() {
            return Err(format!("profile {} already exists", vps.name));
        }
        self.vps.push(vps);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        let before = self.vps.len();
        self.vps.retain(|vps| vps.name != name);
        if self.vps.len() == before {
            return Err(format!("no profile named {name}"));
        }
        Ok(())
    }
}

/// `RTUN_MANAGER_HOME/profiles.toml`, если переменная задана; иначе каталог
/// пользователя: `%APPDATA%\rtun` на Windows, `~/.config/rtun` иначе.
pub fn profiles_path() -> Result<PathBuf, String> {
    if let Some(home) = std::env::var_os("RTUN_MANAGER_HOME") {
        return Ok(PathBuf::from(home).join("profiles.toml"));
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    };
    base.map(|dir| dir.join("rtun").join("profiles.toml"))
        .ok_or_else(|| "cannot find a config directory; set RTUN_MANAGER_HOME".into())
}

/// Имя профиля: буквы, цифры, `-` и `_`. Попадает в пути и вывод, поэтому строго.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Хост: домен или IP (включая IPv6 без скобок).
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vps(name: &str) -> Vps {
        Vps {
            name: name.into(),
            host: "203.0.113.10".into(),
            port: 22,
            user: "root".into(),
            key_path: None,
            domain: None,
            email: None,
        }
    }

    #[test]
    fn add_rejects_duplicates_and_remove_requires_existing() {
        let mut profiles = Profiles::default();
        profiles.add(vps("main")).unwrap();
        assert!(profiles.add(vps("main")).is_err());
        assert!(profiles.remove("missing").is_err());
        profiles.remove("main").unwrap();
        assert!(profiles.vps.is_empty());
    }

    #[test]
    fn save_and_load_round_trip_without_secrets() {
        let dir = std::env::temp_dir().join(format!("rtun-profiles-{}", std::process::id()));
        let path = dir.join("profiles.toml");
        let mut profiles = Profiles::default();
        profiles.add(vps("main")).unwrap();
        profiles.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.to_ascii_lowercase().contains("password"));
        assert_eq!(Profiles::load(&path).unwrap(), profiles);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let path = std::env::temp_dir().join("rtun-profiles-does-not-exist.toml");
        assert_eq!(Profiles::load(&path).unwrap(), Profiles::default());
    }

    #[test]
    fn name_and_host_allowlists() {
        assert!(valid_name("main-vps_1"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name(""));
        assert!(valid_host("vpn.example.com"));
        assert!(valid_host("2001:db8::1"));
        assert!(!valid_host("host;rm -rf /"));
    }
}
