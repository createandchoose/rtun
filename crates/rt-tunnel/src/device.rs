use std::time::Duration;

use tun::AsyncDevice;

use crate::error::TunnelError;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TunnelStats {
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub loss: f32,
    pub rtt: Option<Duration>,
}

pub fn open_tun(name: &str, mtu: u16) -> Result<AsyncDevice, TunnelError> {
    if name.trim().is_empty() || name.len() > 15 {
        return Err(TunnelError::Config(
            "tun name must be 1..=15 characters".into(),
        ));
    }
    if !(1280..=1500).contains(&mtu) {
        return Err(TunnelError::Config("tun mtu must be in 1280..=1500".into()));
    }
    let mut configuration = tun::Configuration::default();
    configuration.tun_name(name).mtu(mtu).up();
    tun::create_as_async(&configuration).map_err(|error| {
        TunnelError::Io(std::io::Error::other(format!(
            "cannot create tun device {name}: {error}"
        )))
    })
}
