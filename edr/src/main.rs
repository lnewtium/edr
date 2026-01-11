mod agent;
mod event;
mod identity;
mod model;
mod syscalls;
mod train;
mod util;

use crate::event::{extract_event, RustEvent};
use crate::model::open_db;
use crate::train::train;
use crate::util::memlock;
use aya::programs::TracePoint;
use aya::{Ebpf, include_bytes_aligned, maps::RingBuf};
use clap::Parser;
use env_logger::{Builder, Env};
use log::{LevelFilter, info, warn};
use std::path::PathBuf;
use tokio::signal;
use crate::agent::agent;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/var/db/edr.db")]
    db: PathBuf,
    #[clap(short, long, default_value = "train")]
    mode: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set default log level to "info" if RUST_LOG is not set
    // Allows override via RUST_LOG environment variable if desired
    Builder::new()
        .filter_level(LevelFilter::Info) // Change to Debug, Trace, etc. as needed
        .parse_env(Env::default().default_filter_or("info")) // fallback if RUST_LOG unset
        .init();
    let opt = Opt::parse();
    if opt.mode != "train" && opt.mode != "agent" {
        warn!("Only 'train' and 'agent' modes are supported.");
        return Ok(());
    }
    memlock();
    let conn = open_db(opt.db);

    // Load eBPF program
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/edr")))?;

    // Attach all tracepoints
    let program: &mut TracePoint = ebpf.program_mut("execve_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = ebpf.program_mut("open_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_open")?;

    let program: &mut TracePoint = ebpf.program_mut("bind_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_bind")?;

    let program: &mut TracePoint = ebpf.program_mut("connect_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_connect")?;

    // Get ring buffer
    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())
        .map_err(|e| anyhow::anyhow!("Failed to create RingBuf: {}", e))?;

    info!("Tracing syscalls. Waiting for events... (Ctrl-C to exit)");

    // Use AsyncFd for non-blocking poll on the ring buffer
    let mut async_ring = tokio::io::unix::AsyncFd::new(ring_buf)
        .map_err(|e| anyhow::anyhow!("Failed to create AsyncFd: {}", e))?;

    loop {
        tokio::select! {
            // Wait for ring buffer to become readable
            guard = async_ring.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();

                while let Some(raw_event) = ring.next() {
                    let event = match extract_event(raw_event) {
                        Some(event) => event,
                        None => continue,
                    };
                    match &event {
                        RustEvent::Exec(e) => info!("Detected execve! PID: {}", e.pid),
                        RustEvent::Open(e) => info!("Detected open! PID: {}", e.pid),
                        RustEvent::Bind(e) => info!("Detected bind! PID: {}", e.pid),
                        RustEvent::Connect(e) => info!("Detected connect! PID: {}", e.pid),
                    }
                    match &*opt.mode {
                        "agent" => {
                            if let Err(e) = agent(&conn, &event) {
                                info!("Agent error: {}", e);
                            }
                        }
                        "train" => {
                            if let Err(e) = train(&conn, &event) {
                                info!("Train error: {}", e);
                            }
                        }
                        _ => {}
                    }
                }


                // Clear readiness to wait again
                guard.clear_ready();
            }

            // Handle Ctrl-C
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C, exiting...");
                break;
            }
        }
    }

    Ok(())
}
