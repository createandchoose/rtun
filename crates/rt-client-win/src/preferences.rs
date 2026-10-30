use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    #[default]
    Direct,
    Vpn,
}
impl RuleMode {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Vpn => "vpn",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Site,
    Application,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub kind: RuleKind,
    pub target: String,
    pub name: String,
    pub mode: RuleMode,
    #[serde(default)]
    pub icon: Option<PathBuf>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportChoice {
    #[default]
    Auto,
    Udp,
    Https,
}
fn yes() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartPreferences {
    #[serde(default = "yes")]
    pub bypass_russia: bool,
    #[serde(default)]
    pub transport: TransportChoice,
    #[serde(default)]
    pub rules: Vec<FilterRule>,
}
impl Default for SmartPreferences {
    fn default() -> Self {
        Self {
            bypass_russia: true,
            transport: TransportChoice::Auto,
            rules: Vec::new(),
        }
    }
}
pub fn data_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("rtun")
}
impl SmartPreferences {
    pub fn load() -> Result<Self, String> {
        let path = data_dir().join("smart.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
        let path = data_dir().join("smart.json");
        let temp = data_dir().join("smart.json.tmp");
        std::fs::write(
            &temp,
            serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(temp, path).map_err(|e| e.to_string())
    }
}

pub fn normalize_site(value: &str) -> Result<String, String> {
    let value = value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = value
        .split('/')
        .next()
        .unwrap_or("")
        .trim_start_matches("*.")
        .trim_end_matches('.');
    if host.contains([':', '@', '?', '#', ' ']) || !host.contains('.') {
        return Err("Укажите домен сайта, например example.com".into());
    }
    let ascii = rt_proto::routing::normalize_domain(host).map_err(|e| e.to_string())?;
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("Некорректное доменное имя".into());
    }
    Ok(ascii)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_migration() {
        let prefs: SmartPreferences = serde_json::from_str("{}").unwrap();
        assert!(prefs.bypass_russia);
        assert_eq!(prefs.transport, TransportChoice::Auto);
        assert_eq!(
            normalize_site("https://Example.RU/path").unwrap(),
            "example.ru"
        );
        assert!(normalize_site("abc;echo test").is_err());
        assert!(normalize_site("a;evil.com").is_err());
        assert_eq!(
            normalize_site("пример.рф").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );
    }

    #[test]
    fn settings_round_trip_keeps_icons_and_modes() {
        let mut prefs = SmartPreferences {
            bypass_russia: false,
            transport: TransportChoice::Https,
            rules: Vec::new(),
        };
        prefs.rules.push(FilterRule {
            kind: RuleKind::Application,
            target: r"C:\Apps\tool.exe".into(),
            name: "Tool".into(),
            mode: RuleMode::Vpn,
            icon: Some(PathBuf::from(r"C:\cache\tool.png")),
        });
        prefs.rules.push(FilterRule {
            kind: RuleKind::Site,
            target: "example.ru".into(),
            name: "Example".into(),
            mode: RuleMode::Direct,
            icon: Some(PathBuf::from(r"C:\cache\site.png")),
        });
        let loaded: SmartPreferences =
            serde_json::from_slice(&serde_json::to_vec(&prefs).unwrap()).unwrap();
        assert!(!loaded.bypass_russia);
        assert_eq!(loaded.transport, TransportChoice::Https);
        assert_eq!(loaded.rules[0].mode, RuleMode::Vpn);
        assert_eq!(loaded.rules[0].icon, prefs.rules[0].icon);
        assert_eq!(loaded.rules[1].kind, RuleKind::Site);
        assert_eq!(loaded.rules[1].icon, prefs.rules[1].icon);
    }
}
