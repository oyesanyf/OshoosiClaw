# Cross-Platform EDR Sensor Implementation in Rust

To build a cross-platform EDR sensor in Rust, you generally need to separate your Kernel-Interaction Logic (which is platform-specific) from your Telemetry Logic (which is shared).

Below are the boilerplate implementations for each. Note that for a production EDR, these would usually be separate crates in a workspace, as they require different dependencies and compilation targets (especially Linux eBPF).

## 1. Windows: WFP (Using wfp-rs)
For Windows, we use a wrapper around the Windows Filtering Platform. This allows you to subscribe to events like ConnectV4 to see outbound traffic.

### Cargo.toml
```toml
[dependencies]
wfp = "0.0.5"
tokio = { version = "1", features = ["full"] }
```

### main.rs
```rust
use wfp::{FilterEngineBuilder, FilterBuilder, ActionType, Layer, Transaction};
use std::io;

fn main() -> io::Result<()> {
    // 1. Open the WFP Engine
    let mut engine = FilterEngineBuilder::default().dynamic().open()?;
    
    // 2. Start a transaction to add our monitor
    let transaction = Transaction::new(&mut engine)?;

    // 3. Define a "Listen" filter (we use 'Permit' or 'Inspect' to monitor without blocking)
    FilterBuilder::default()
        .name("EDR Network Monitor")
        .description("Observing all outbound IPv4 traffic")
        .action(ActionType::Permit) // We aren't blocking, just seeing
        .layer(Layer::ConnectV4)
        .add(&transaction)?;

    transaction.commit()?;
    println!("Windows WFP Sensor Active. Monitoring network layer...");

    // Keep alive to receive callbacks
    std::thread::park();
    Ok(())
}
```

## 2. macOS: Endpoint Security (Using endpoint-sec)
On macOS, you must use the System Extension framework. This code requires the `com.apple.developer.endpoint-security.client` entitlement to run.

### Cargo.toml
```toml
[target.'cfg(target_os = "macos")'.dependencies]
endpoint-sec = "0.5.1"
```

### main.rs
```rust
#[cfg(target_os = "macos")]
use endpoint_sec::{Client, Event};

fn main() {
    #[cfg(target_os = "macos")]
    {
        // 1. Create the ES Client with a handler callback
        let client = Client::new(|_client, message| {
            match message.event() {
                Event::Open(ev) => {
                    println!("File Open Detected: {}", ev.file().path());
                }
                Event::Connect(ev) => {
                    println!("Network Connection: Destination {}", ev.address());
                }
                _ => (),
            }
        }).expect("Failed to create ES Client. Are you running with proper entitlements?");

        // 2. Subscribe to the events we want to monitor
        client.subscribe(&[Event::Connect]).unwrap();
        
        println!("macOS Endpoint Security Sensor Active.");
        loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
    }
}
```

## 3. Linux: eBPF (Using Aya)
Linux uses eBPF to hook the kernel. This is split into two parts: the Kernel-space code (that runs in the stack) and the User-space loader (that ships the data).

### Kernel-space (ebpf/src/main.rs)
```rust
#![no_std]
#![no_main]
use aya_bpf::{macros::kprobe, programs::KprobeContext};

#[kprobe]
pub fn handle_tcp_connect(ctx: KprobeContext) -> u32 {
    // In a real EDR, you'd use bpf_get_current_pid_tgid() 
    // and send the data to userspace via a RingBuffer.
    0 
}
```

### User-space (src/main.rs)
```rust
use aya::{Ebpf, programs::Kprobe};

fn main() -> Result<(), anyhow::Error> {
    // 1. Load the compiled BPF bytecode
    let mut bpf = Ebpf::load(include_bytes_aligned!("../target/bpfel-unknown-none/debug/edr-ebpf"))?;
    
    // 2. Attach to the kernel function for TCP connections
    let program: &mut Kprobe = bpf.program_mut("handle_tcp_connect").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_v4_connect", 0)?;

    println!("Linux eBPF Sensor Active. Hooked tcp_v4_connect.");
    std::thread::park();
    Ok(())
}
```

## Summary of Implementation Logic
### How to manage this "Unified" code:
To keep your project clean, use Conditional Compilation (`#[cfg(target_os = "...")])` or create a Trait that abstracts the "Start Monitoring" function:
- **Trait Sensor**: Defines `fn start_monitoring(&self)`.
- **Impl for Windows**: Uses `wfp-rs`.
- **Impl for macOS**: Uses `endpoint-sec`.
- **Impl for Linux**: Uses `aya`.

### A Crucial Warning on Privileges:
- **Windows**: Must run as Administrator (and eventually as a PPL service).
- **macOS**: Must be signed with an Endpoint Security Entitlement from Apple and run as root.
- **Linux**: Requires `CAP_BPF` or root privileges to load eBPF programs into the kernel.
