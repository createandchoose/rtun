use crate::{push_event, render as render_window, MainWindow, RuleItem, Shared, LEVEL_ERROR};
use rt_client_win::preferences::{self, FilterRule, RuleKind, RuleMode, SmartPreferences};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::{
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};
use tokio::runtime::Handle;

pub fn render(ui: &MainWindow, prefs: &SmartPreferences) {
    ui.set_rf_enabled(prefs.bypass_russia);
    ui.set_transport_caption("obfs-udp".into());
    let rows: Vec<RuleItem> = prefs
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| RuleItem {
            index: index as i32,
            name: rule.name.clone().into(),
            target: rule.target.clone().into(),
            application: rule.kind == RuleKind::Application,
            direct: rule.mode == RuleMode::Direct,
            icon: rule
                .icon
                .as_ref()
                .and_then(|path| slint::Image::load_from_path(path).ok())
                .unwrap_or_default(),
        })
        .collect();
    ui.set_rules(ModelRc::new(VecModel::from(rows)));
}

fn change(ui: &MainWindow, shared: &Shared, update: impl FnOnce(&mut SmartPreferences)) {
    let mut state = shared.lock().unwrap();
    let before = state.preferences.clone();
    update(&mut state.preferences);
    if let Err(error) = state.preferences.save() {
        state.preferences = before;
        push_event(
            &mut state,
            format!("Не удалось сохранить настройки: {error}"),
            LEVEL_ERROR,
        );
    }
    render_window(ui, &state);
}

fn ps_quote(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "''"))
}
async fn fetch_icon_file(url: &str, path: &Path) -> bool {
    let mut command = tokio::process::Command::new("curl.exe");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
        .args([
            "--fail",
            "--silent",
            "--location",
            "--max-time",
            "10",
            "--max-filesize",
            "2097152",
            "--output",
        ])
        .arg(path)
        .arg(url)
        .kill_on_drop(true)
        .output()
        .await
        .is_ok_and(|result| result.status.success())
}

fn favicon_url(html: &str, host: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    for offset in lower.match_indices("<link").map(|(offset, _)| offset) {
        let end = lower[offset..].find('>')? + offset;
        let tag = &lower[offset..end];
        if !tag.contains("icon") {
            continue;
        }
        let href = tag.find("href")? + offset + 4;
        let rest = html[href..end].trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        let quote = rest.chars().next()?;
        if quote != '\'' && quote != '"' {
            continue;
        }
        let value = rest[1..].split(quote).next()?;
        if value.starts_with("https://") || value.starts_with("http://") {
            return Some(value.into());
        }
        if value.starts_with("//") {
            return Some(format!("https:{value}"));
        }
        if !value.starts_with("data:") {
            return Some(format!("https://{host}/{}", value.trim_start_matches('/')));
        }
    }
    None
}
async fn icon(rule: &FilterRule) -> Option<PathBuf> {
    let dir = preferences::data_dir().join("icons");
    std::fs::create_dir_all(&dir).ok()?;
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    rule.target.hash(&mut hash);
    let destination = dir.join(format!("{:x}.png", hash.finish()));
    if destination.is_file() {
        return Some(destination);
    }
    let vector = destination.with_extension("svg");
    if vector.is_file() {
        return Some(vector);
    }
    let source = dir.join(format!("{:x}.ico", hash.finish()));
    let script = if rule.kind == RuleKind::Application {
        format!("Add-Type -AssemblyName System.Drawing; $i=[System.Drawing.Icon]::ExtractAssociatedIcon({}); if($i){{$b=$i.ToBitmap(); $b.Save({},[System.Drawing.Imaging.ImageFormat]::Png);$b.Dispose();$i.Dispose()}}",ps_quote(Path::new(&rule.target)),ps_quote(&destination))
    } else {
        let url = format!("https://{}/favicon.ico", rule.target);
        if !fetch_icon_file(&url, &source).await {
            let html_path = source.with_extension("html");
            if !fetch_icon_file(&format!("https://{}/", rule.target), &html_path).await {
                return None;
            }
            let html = std::fs::read_to_string(&html_path).ok()?;
            let _ = std::fs::remove_file(html_path);
            let url = favicon_url(&html, &rule.target)?;
            if !fetch_icon_file(&url, &source).await {
                return None;
            }
        }
        if std::fs::read_to_string(&source).is_ok_and(|text| text.contains("<svg")) {
            std::fs::rename(&source, &vector).ok()?;
            return Some(vector);
        }
        format!("Add-Type -AssemblyName System.Drawing; try{{$i=[System.Drawing.Image]::FromFile({});$i.Save({},[System.Drawing.Imaging.ImageFormat]::Png);$i.Dispose()}}catch{{$i=New-Object System.Drawing.Icon({});$b=$i.ToBitmap();$b.Save({},[System.Drawing.Imaging.ImageFormat]::Png);$b.Dispose();$i.Dispose()}}",ps_quote(&source),ps_quote(&destination),ps_quote(&source),ps_quote(&destination))
    };
    let mut command = tokio::process::Command::new("powershell");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let _ = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .kill_on_drop(true)
        .output()
        .await;
    let _ = std::fs::remove_file(source);
    destination.is_file().then_some(destination)
}

#[cfg(debug_assertions)]
pub fn preview(ui: &MainWindow, runtime: &tokio::runtime::Runtime, output: PathBuf) {
    let mut prefs = SmartPreferences::default();
    for (kind, target, name, mode) in [
        (RuleKind::Site, "github.com", "GitHub", RuleMode::Vpn),
        (RuleKind::Site, "yandex.ru", "Яндекс", RuleMode::Direct),
        (
            RuleKind::Application,
            r"C:\Windows\System32\notepad.exe",
            "Блокнот",
            RuleMode::Direct,
        ),
    ] {
        let mut rule = FilterRule {
            kind,
            target: target.into(),
            name: name.into(),
            mode,
            icon: None,
        };
        rule.icon = runtime.block_on(icon(&rule));
        prefs.rules.push(rule);
    }
    render(ui, &prefs);
    ui.set_screen(2);
    if std::env::var_os("RTUN_PREVIEW_APPS").is_some() {
        ui.set_filter_tab(1);
    }
    let weak = ui.as_weak();
    slint::Timer::single_shot(std::time::Duration::from_millis(900), move || {
        if let Some(ui) = weak.upgrade() {
            if let Ok(image) = ui.window().take_snapshot() {
                let _ = std::fs::write(output.with_extension("rgba"), image.as_bytes());
                let _ = std::fs::write(
                    output.with_extension("json"),
                    format!("[{},{}]", image.width(), image.height()),
                );
            }
        }
        let _ = slint::quit_event_loop();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovers_site_owned_favicons() {
        assert_eq!(
            favicon_url("<link rel='icon' href='/assets/icon.png'>", "example.com").unwrap(),
            "https://example.com/assets/icon.png"
        );
        assert_eq!(
            favicon_url(
                "<link rel=\"shortcut icon\" href=\"https://cdn.example.com/i.ico\">",
                "example.com"
            )
            .unwrap(),
            "https://cdn.example.com/i.ico"
        );
    }
    #[tokio::test]
    #[ignore = "downloads a favicon and extracts a Windows application icon"]
    async fn persists_site_and_application_icons() {
        for (kind, target) in [
            (RuleKind::Site, "github.com"),
            (RuleKind::Application, r"C:\Windows\System32\notepad.exe"),
        ] {
            let rule = FilterRule {
                kind,
                target: target.into(),
                name: "test".into(),
                mode: RuleMode::Direct,
                icon: None,
            };
            let path = icon(&rule).await.expect("original icon");
            assert!(std::fs::read(&path)
                .unwrap()
                .starts_with(b"\x89PNG\r\n\x1a\n"));
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            assert_eq!(icon(&rule).await.unwrap(), path);
            assert_eq!(
                std::fs::metadata(path).unwrap().modified().unwrap(),
                modified
            );
        }
    }
}

fn add(ui: &MainWindow, shared: &Shared, handle: &Handle, mut rule: FilterRule) {
    if shared
        .lock()
        .unwrap()
        .preferences
        .rules
        .iter()
        .any(|old| old.kind == rule.kind && old.target.eq_ignore_ascii_case(&rule.target))
    {
        return;
    }
    // A cached vector fallback keeps every row identifiable even if a site has no favicon.
    let fallback = preferences::data_dir().join("icons/fallback.svg");
    let _ = std::fs::create_dir_all(fallback.parent().unwrap());
    if !fallback.exists() {
        let _ = std::fs::write(
            &fallback,
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"><rect width="48" height="48" rx="12" fill="#162337"/><circle cx="24" cy="24" r="13" fill="none" stroke="#78b7ff" stroke-width="2"/><path d="M11 24h26M24 11c-8 8-8 18 0 26M24 11c8 8 8 18 0 26" fill="none" stroke="#78b7ff" stroke-width="2"/></svg>"##,
        );
    }
    rule.icon = Some(fallback);
    change(ui, shared, |prefs| prefs.rules.push(rule.clone()));
    let weak = ui.as_weak();
    let shared = shared.clone();
    handle.spawn(async move {
        if let Some(icon) = icon(&rule).await {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    change(&ui, &shared, |prefs| {
                        if let Some(found) = prefs
                            .rules
                            .iter_mut()
                            .find(|old| old.kind == rule.kind && old.target == rule.target)
                        {
                            found.icon = Some(icon);
                        }
                    });
                }
            });
        }
    });
}

pub fn bind(ui: &MainWindow, shared: &Shared, handle: &Handle) {
    ui.on_rf_changed({
        let weak = ui.as_weak();
        let shared = shared.clone();
        move |enabled| {
            if let Some(ui) = weak.upgrade() {
                change(&ui, &shared, |prefs| prefs.bypass_russia = enabled);
            }
        }
    });
    ui.on_rule_mode({
        let weak = ui.as_weak();
        let shared = shared.clone();
        move |index| {
            if let Some(ui) = weak.upgrade() {
                change(&ui, &shared, |prefs| {
                    if let Some(rule) = prefs.rules.get_mut(index as usize) {
                        rule.mode = if rule.mode == RuleMode::Direct {
                            RuleMode::Vpn
                        } else {
                            RuleMode::Direct
                        };
                    }
                });
            }
        }
    });
    ui.on_rule_remove({
        let weak = ui.as_weak();
        let shared = shared.clone();
        move |index| {
            if let Some(ui) = weak.upgrade() {
                change(&ui, &shared, |prefs| {
                    if (index as usize) < prefs.rules.len() {
                        prefs.rules.remove(index as usize);
                    }
                });
            }
        }
    });
    ui.on_add_site({
        let weak = ui.as_weak();
        let shared = shared.clone();
        let handle = handle.clone();
        move |value| {
            if let Some(ui) = weak.upgrade() {
                match preferences::normalize_site(value.as_str()) {
                    Ok(site) => {
                        add(
                            &ui,
                            &shared,
                            &handle,
                            FilterRule {
                                kind: RuleKind::Site,
                                name: site.clone(),
                                target: site,
                                mode: RuleMode::Vpn,
                                icon: None,
                            },
                        );
                        ui.set_site_input("".into());
                    }
                    Err(error) => {
                        let mut state = shared.lock().unwrap();
                        push_event(&mut state, error, LEVEL_ERROR);
                        render_window(&ui, &state);
                    }
                }
            }
        }
    });
    ui.on_add_application({
        let weak = ui.as_weak();
        let shared = shared.clone();
        let handle = handle.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Приложения Windows", &["exe"])
                    .pick_file()
                {
                    add(
                        &ui,
                        &shared,
                        &handle,
                        FilterRule {
                            kind: RuleKind::Application,
                            name: path
                                .file_stem()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned(),
                            target: path.to_string_lossy().into_owned(),
                            mode: RuleMode::Vpn,
                            icon: None,
                        },
                    );
                }
            }
        }
    });
}
