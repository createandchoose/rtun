# Автоустановка на VPS и менеджер конфигов

Цель: пользователь вводит данные своего VPS (IP/домен, SSH-доступ), а программа
сама ставит сервер RTUN, создает пира и отдает клиентский конфиг в формате
WireGuard (`.conf`). Аналогично AmneziaVPN, но на текущем стеке RTUN.

Этот документ — контракт между частями. Агенты реализуют свои модули строго по
сигнатурам ниже.

## Компоненты

| Крейт | Роль | Владелец |
|---|---|---|
| `rt-proto` (модуль `wgconf`) | разбор и запись WG-подобного `.conf`, конвертация в/из `ClientConfig` | wgconf |
| `rt-deploy` (новый) | SSH-подключение, установка сервера, создание пира | deploy |
| `rtun-manager` (новый бинарь) | CLI-менеджер: профили VPS, деплой, экспорт/импорт конфигов | manager |

Сервер (`rtund`, `rt-ctl`, `packaging/server/install.sh`) уже есть и не меняется
без необходимости. Клиентский демон и GUI не трогаются этой работой.

## Формат конфига (WireGuard-стиль)

Клиентский файл `rtun-<peer>.conf`:

```ini
[Interface]
PrivateKey = <base64>
Address = 10.66.0.2/32, fd66:1::2/128
DNS = 127.0.0.53
MTU = 1360

[Peer]
PublicKey = <base64>
PresharedKey = <base64, optional>
Endpoint = vpn.example.com:443
PersistentKeepalive = 25

[Rtun]
Transports = obfs-udp, ws-tls
WsPath = /ws
Alpn = http/1.1
MtuWs = 1280
ObfsH1 = 3054197761
ObfsH2 = 3054197762
ObfsH3 = 3054197763
ObfsH4 = 3054197764
PaddingMax = 8
JunkCount = 4
JunkMin = 80
JunkMax = 300
DirectSuffixes = ru, рф, xn--p1ai, su, moscow, москва, xn--80adxhks
```

- Секции `[Interface]` и `[Peer]` совместимы с полями WireGuard по смыслу.
- Секция `[Rtun]` — расширение, стандартный WG-клиент ее игнорирует.
- Комментарии `#` разрешены. Неизвестные ключи — ошибка (не молча).
- Приватный ключ пишется через `rt_proto::config::write_secure` (0600).

### API модуля `rt_proto::wgconf`

```rust
pub struct WgConf { /* Interface, Peer, Rtun */ }
impl WgConf {
    pub fn parse(text: &str) -> Result<Self, ConfigError>;
    pub fn to_text(&self) -> String;
    pub fn from_client(cfg: &ClientConfig) -> Self;  // ClientConfig -> WgConf
    pub fn into_client(self) -> Result<ClientConfig, ConfigError>; // полный ClientConfig
    pub fn load(path: &Path) -> Result<Self, ConfigError>;
    pub fn save(&self, path: &Path) -> Result<(), ConfigError>; // write_secure
}
```

Поля `ClientConfig` (`rt_proto::config`) должны совпадать с файлом
`client.toml`, который уже понимает демон. Конвертация двусторонняя и без потерь
(тест round-trip).

## Деплой (`rt-deploy`)

### SSH-абстракция

```rust
pub enum SshAuth {
    Password(String),   // не сохраняется на диск
    KeyFile(PathBuf),   // путь к приватному ключу
}

pub struct VpsTarget {
    pub host: String,      // IP или домен
    pub port: u16,         // по умолчанию 22
    pub user: String,      // по умолчанию root
}

#[async_trait]
pub trait Remote: Send {
    async fn exec(&mut self, cmd: &str) -> Result<ExecOutput, DeployError>;
    async fn upload(&mut self, local: &Path, remote: &str, mode: u32) -> Result<(), DeployError>;
    async fn download(&mut self, remote: &str) -> Result<Vec<u8>, DeployError>;
}

pub struct ExecOutput { pub status: i32, pub stdout: String, pub stderr: String }
```

- Реализации: `RusshRemote` (настоящий SSH, крейт `russh`) и `MockRemote`
  (для тестов: записывает команды, отдает заранее заданные ответы).
- Пароль и ключ никогда не логируются. Команды с секретами в `tracing` не пишутся.

### Пайплайн деплоя

```rust
pub struct DeployPlan {
    pub target: VpsTarget,
    pub auth: SshAuth,
    pub domain: String,    // домен, указывающий на VPS
    pub email: String,     // для Let's Encrypt
    pub peer_name: String,
    pub peer_index: u8,
    pub server_binaries: PathBuf, // каталог с rtund и rt-ctl (x86_64 linux)
}

pub async fn deploy(plan: &DeployPlan, remote: &mut dyn Remote,
                    progress: &mut dyn FnMut(Step)) -> Result<DeployResult, DeployError>;

pub struct DeployResult {
    pub client_conf: WgConf,  // готовый конфиг для клиента
}
```

Шаги (`Step`) для прогресса в CLI и GUI:
1. `Probe` — `uname -m`, `/etc/os-release`; только Ubuntu 22.04+/Debian 12, x86_64.
2. `Upload` — копирование `rtund`, `rt-ctl`, `packaging/server/*`.
3. `Install` — `install.sh --domain ... --email ...` (идемпотентен).
4. `Peer` — `rt-ctl add-peer ...` (если пира нет).
5. `Fetch` — скачать `/etc/rtun/peers/<name>.toml` или `rt-ctl gen-client`,
   собрать `WgConf` через `rt_proto::wgconf`.
6. `Verify` — `systemctl is-active rtund nginx unbound`, порт 443 открыт.

Каждый шаг идемпотентен. При ошибке деплой останавливается и возвращает шаг,
на котором упал, и stderr.

## Менеджер (`rtun-manager`)

Один бинарь, CLI. Профили хранятся в
`$XDG_CONFIG_HOME/rtun/profiles.toml` (0600). В файле — только адрес, порт,
пользователь, домен, email и путь к ключу. Пароли в файл не пишутся.

Команды:

```text
rtun-manager vps add <name> --host IP --user root [--port 22] [--key PATH]
rtun-manager vps list
rtun-manager vps remove <name>
rtun-manager deploy <name> --domain vpn.example.com --email a@b.c [--peer laptop]
                            # пароль спрашивается интерактивно, если нет --key
rtun-manager peer add <vps> <name>      # новый пир на уже стоящем сервере
rtun-manager conf export <vps> <peer> -o rtun-laptop.conf
rtun-manager conf import rtun-laptop.conf -o /etc/rtun/client.toml
rtun-manager status <vps>               # systemctl-проверка
```

Без данных VPS: команды `conf import/export` и `vps` работают без сети,
`deploy` проверяется на `MockRemote`.

## Тестирование без VPS

- Unit-тесты `wgconf`: парсинг, round-trip, ошибки на неизвестные ключи.
- `rt-deploy` на `MockRemote`: полный пайплайн, порядок шагов, остановка на ошибке.
- `rtun-manager`: интеграционные тесты CLI на временном каталоге профилей.
- Настоящий VPS проверяется позже: вручную пользователем, с инструкцией в
  `docs/deploy.md`. До этого момента помечаем как «не проверено на VPS».

## Вне объема этой итерации

- GUI-вкладка в Slint (после стабилизации CLI).
- Хранение пароля в системном keyring.
- Установка на не-Ubuntu/Debian.
- Удаление сервера с VPS (`uninstall`).
