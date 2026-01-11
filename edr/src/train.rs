use rusqlite::Connection;
use crate::event::{RustEvent, RustExecEvent, RustOpenEvent, RustBindEvent, RustConnectEvent};
use crate::identity::resolve_identity;
use crate::syscalls::insert_program;

pub fn train(conn: &Connection, event: &RustEvent) -> rusqlite::Result<()> {
    match event {
        RustEvent::Exec(e) => train_exec(conn, e),
        RustEvent::Open(e) => train_open(conn, e),
        RustEvent::Bind(e) => train_bind(conn, e),
        RustEvent::Connect(e) => train_connect(conn, e),
    }
}

fn train_exec(conn: &Connection, event: &RustExecEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    insert_program(conn, identity, "execve", &event.filename, &event.args)?;
    Ok(())
}

fn train_open(conn: &Connection, event: &RustOpenEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    insert_program(conn, identity, "open", &event.filename, &vec![])?;
    Ok(())
}

fn train_bind(conn: &Connection, event: &RustBindEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let ip_str = format_ip(&event.ip);
    insert_program(conn, identity, "bind", &ip_str, &vec![])?;
    Ok(())
}

fn train_connect(conn: &Connection, event: &RustConnectEvent) -> rusqlite::Result<()> {
    let identity = match resolve_identity(conn, event.pid) {
        Some(b) => b,
        None => return Ok(()),
    };
    let ip_str = format_ip(&event.ip);
    insert_program(conn, identity, "connect", &ip_str, &vec![])?;
    Ok(())
}

fn format_ip(ip: &[u8; 16]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
