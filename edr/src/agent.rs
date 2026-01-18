use crate::identity::resolve_identity;
use crate::syscalls::select_program_count;
use rusqlite::Connection;
use crate::event::{RustEvent, RustExecEvent, RustOpenEvent, RustBindEvent, RustConnectEvent};

const ALERT_API_URL: &str = "http://localhost:3000/api/events";
static mut SUSPECIOUS_EVENT_COUNTER: u32 = 0;

pub fn agent(conn: &Connection, event: &RustEvent) -> rusqlite::Result<()> {
    match event {
        RustEvent::Exec(e) => agent_exec(conn, e),
        RustEvent::Open(e) => agent_open(conn, e),
        RustEvent::Bind(e) => agent_bind(conn, e),
        RustEvent::Connect(e) => agent_connect(conn, e),
    }
}

fn agent_exec(conn: &Connection, event: &RustExecEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let res = select_program_count(conn, identity, "execve", &event.filename, &event.args)?;
    if res > 0 {
        return Ok(());
    }
    send_alert("execve", event.pid, &event.filename, &event.args);
    Ok(())
}

fn agent_open(conn: &Connection, event: &RustOpenEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let res = select_program_count(conn, identity, "open", &event.filename, &vec![])?;
    if res > 0 {
        return Ok(());
    }
    send_alert("open", event.pid, &event.filename, &vec![]);
    Ok(())
}

fn agent_bind(conn: &Connection, event: &RustBindEvent) -> rusqlite::Result<()> {
    if is_zero_ip(&event.ip) {
        return Ok(());
    }
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let ip_str = format_ip(&event.ip);
    let res = select_program_count(conn, identity, "bind", &ip_str, &vec![])?;
    if res > 0 {
        return Ok(());
    }
    send_alert("bind", event.pid, &ip_str, &vec![]);
    Ok(())
}

fn agent_connect(conn: &Connection, event: &RustConnectEvent) -> rusqlite::Result<()> {
    if is_zero_ip(&event.ip) {
        return Ok(());
    }
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let ip_str = format_ip(&event.ip);
    let res = select_program_count(conn, identity, "connect", &ip_str, &vec![])?;
    if res > 0 {
        return Ok(());
    }
    send_alert("connect", event.pid, &ip_str, &vec![]);
    Ok(())
}

fn format_ip(ip: &[u8; 16]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn is_zero_ip(ip: &[u8; 16]) -> bool {
    ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0
}

fn send_alert(syscall: &str, pid: u32, filename: &str, args: &Vec<String>) {
    unsafe { SUSPECIOUS_EVENT_COUNTER += 1; }
    if unsafe { SUSPECIOUS_EVENT_COUNTER < 10 } {
        println!("Suspecious event counter exceeded threshold, not sending alert.");
        return;
    }

    let syscall = syscall.to_string();
    let filename = filename.to_string();
    let args = args.clone();

    let payload = serde_json::json!({
        "pid": pid,
        "filename": &filename,
        "syscall": &syscall,
        "args": &args,
        "suspecious_event_count": unsafe { SUSPECIOUS_EVENT_COUNTER },
    });

    tokio::spawn(async move {
        let client = reqwest::Client::new();
        match client.post(ALERT_API_URL).json(&payload).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Alert sent successfully for PID {} ({})", pid, &syscall);
                } else {
                    println!("Failed to send alert for PID {}: HTTP {}", pid, response.status());
                }
            }
            Err(e) => {
                println!("Error sending alert for PID {}: {}", pid, e);
            }
        }
    });
}
