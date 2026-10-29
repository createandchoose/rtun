//! Клиент RTUN для Windows: один процесс с движком, wintun-адаптер, netsh.
//! Цикл туннеля повторяет `rt-clientd`, но без systemd-resolved и D-Bus.

pub mod error;
pub mod plan;
pub mod session;
pub mod setup;
pub mod split;
pub mod status;

pub use error::ClientWinError;
pub use session::run;
pub use status::{explain, is_elevated, TunnelState};
