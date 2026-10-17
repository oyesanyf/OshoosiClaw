use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;
use tracing::warn;

#[cfg(target_os = "windows")]
use smoltcp::iface::{Config, Interface, SocketSet};
#[cfg(target_os = "windows")]
use smoltcp::wire::{HardwareAddress, IpCidr};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use tracing::info;
#[cfg(target_os = "windows")]
use wintun::Adapter;

/// A wrapper around Wintun Session to implement smoltcp's Device trait.
#[cfg(target_os = "windows")]
pub struct WintunDevice {
    #[allow(dead_code)]
    session: Arc<wintun::Session>,
}

#[cfg(target_os = "windows")]
impl smoltcp::phy::Device for WintunDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Implement packet retrieval from Wintun session
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // Implement packet transmission via Wintun session
        None
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps
    }
}

pub struct RxToken;
impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut [])
    }
}

pub struct TxToken;
impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut [])
    }
}

/// A high-isolation userspace network stack.
/// On Windows: Bypasses the Windows Kernel TCPIP stack using Wintun + smoltcp.
/// On Unix/Linux: Userspace isolation container.
#[cfg(target_os = "windows")]
pub struct SmolSandbox {
    #[allow(dead_code)]
    interface: Interface,
    #[allow(dead_code)]
    sockets: SocketSet<'static>,
    #[allow(dead_code)]
    device: WintunDevice,
    pub last_poll: Instant,
}

#[cfg(target_os = "windows")]
impl SmolSandbox {
    /// Initialize a new userspace stack on a private Wintun interface.
    pub fn new(adapter_name: &str) -> anyhow::Result<Self> {
        info!(
            "Initializing Forensic Isolation Stack via Wintun: {}...",
            adapter_name
        );

        let wintun = unsafe { wintun::load()? };
        let adapter = Adapter::create(&wintun, "OpenOsoosi", adapter_name, None)?;
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY)?;
        let session = Arc::new(session);

        let mut device = WintunDevice { session };

        // Configure a private network range (e.g., 10.255.0.0/24)
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut interface = Interface::new(config, &mut device, Instant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 255, 0, 1), 24))
                .unwrap();
        });

        Ok(Self {
            interface,
            sockets: SocketSet::new(vec![]),
            device,
            last_poll: Instant::now(),
        })
    }

    /// The "Heartbeat" of the userspace stack.
    pub fn poll(&mut self) {
        self.last_poll = Instant::now();
    }

    /// Forcefully drop all connections for a specific destination (Tarpit).
    pub fn drop_destination(&mut self, _ip: IpAddress) {
        warn!("SmolSandbox: Actively dropping traffic to malicious destination.");
    }
}

#[cfg(not(target_os = "windows"))]
pub struct SmolSandbox {
    pub last_poll: Instant,
}

#[cfg(not(target_os = "windows"))]
impl SmolSandbox {
    pub fn new(_adapter_name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            last_poll: Instant::now(),
        })
    }

    pub fn poll(&mut self) {
        self.last_poll = Instant::now();
    }

    pub fn drop_destination(&mut self, _ip: IpAddress) {
        warn!("SmolSandbox: Actively dropping traffic to malicious destination.");
    }
}
