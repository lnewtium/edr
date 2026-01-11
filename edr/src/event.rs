use std::ffi::CStr;
use aya::maps::ring_buf::RingBufItem;
use log::warn;
use edr_common::{ExecEvent, OpenEvent, BindEvent, ConnectEvent};
use std::mem::size_of;

#[derive(Debug, Clone)]
pub enum RustEvent {
    Exec(RustExecEvent),
    Open(RustOpenEvent),
    Bind(RustBindEvent),
    Connect(RustConnectEvent),
}

#[derive(Debug, Clone)]
pub struct RustExecEvent {
    pub pid: u32,
    pub filename: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RustOpenEvent {
    pub pid: u32,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub struct RustBindEvent {
    pub pid: u32,
    pub ip: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct RustConnectEvent {
    pub pid: u32,
    pub ip: [u8; 16],
}

pub fn extract_event(raw_event: RingBufItem) -> Option<RustEvent> {
    if raw_event.len() < 8 {
        warn!("Received truncated event");
        return None;
    }

    // Read event type (first field)
    let event_type = unsafe { *(raw_event.as_ptr() as *const u32) };

    match event_type {
        1 => { // EventType::Exec
            if raw_event.len() < size_of::<ExecEvent>() {
                warn!("Received truncated ExecEvent");
                return None;
            }
            let event = unsafe { std::ptr::read(raw_event.as_ptr() as *const ExecEvent) };
            Some(RustEvent::Exec(rustify_exec_event(&event)))
        }
        2 => { // EventType::Open
            if raw_event.len() < size_of::<OpenEvent>() {
                warn!("Received truncated OpenEvent");
                return None;
            }
            let event = unsafe { std::ptr::read(raw_event.as_ptr() as *const OpenEvent) };
            Some(RustEvent::Open(rustify_open_event(&event)))
        }
        3 => { // EventType::Bind
            if raw_event.len() < size_of::<BindEvent>() {
                warn!("Received truncated BindEvent");
                return None;
            }
            let event = unsafe { std::ptr::read(raw_event.as_ptr() as *const BindEvent) };
            Some(RustEvent::Bind(rustify_bind_event(&event)))
        }
        4 => { // EventType::Connect
            if raw_event.len() < size_of::<ConnectEvent>() {
                warn!("Received truncated ConnectEvent");
                return None;
            }
            let event = unsafe { std::ptr::read(raw_event.as_ptr() as *const ConnectEvent) };
            Some(RustEvent::Connect(rustify_connect_event(&event)))
        }
        _ => {
            warn!("Unknown event type: {}", event_type);
            None
        }
    }
}

fn rustify_exec_event(event: &ExecEvent) -> RustExecEvent {
    let filename = CStr::from_bytes_until_nul(&event.filename)
        .ok()
        .and_then(|cstr| cstr.to_str().ok())
        .unwrap_or("");
    let mut args_vec = Vec::new();
    for i in 0..event.argc as usize {
        let arg = CStr::from_bytes_until_nul(&event.args[i])
            .ok()
            .and_then(|cstr| cstr.to_str().ok())
            .unwrap_or("");
        args_vec.push(arg.to_string());
    }
    RustExecEvent {
        pid: event.pid,
        filename: filename.to_string(),
        args: args_vec,
    }
}

fn rustify_open_event(event: &OpenEvent) -> RustOpenEvent {
    let filename = CStr::from_bytes_until_nul(&event.filename)
        .ok()
        .and_then(|cstr| cstr.to_str().ok())
        .unwrap_or("");
    RustOpenEvent {
        pid: event.pid,
        filename: filename.to_string(),
    }
}

fn rustify_bind_event(event: &BindEvent) -> RustBindEvent {
    RustBindEvent {
        pid: event.pid,
        ip: event.ip,
    }
}

fn rustify_connect_event(event: &ConnectEvent) -> RustConnectEvent {
    RustConnectEvent {
        pid: event.pid,
        ip: event.ip,
    }
}
