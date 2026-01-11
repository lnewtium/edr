#![no_std]

pub const MAX_ARGS: usize = 16;
pub const MAX_ARG_LEN: usize = 96;
pub const MAX_PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum EventType {
    Exec = 1,
    Open = 2,
    Bind = 3,
    Connect = 4,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ExecEvent {
    pub _type: EventType,
    pub pid: u32,
    pub filename: [u8; MAX_PATH_LEN],
    pub args: [[u8; MAX_ARG_LEN]; MAX_ARGS],
    pub argc: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct OpenEvent {
    pub _type: EventType,
    pub pid: u32,
    pub filename: [u8; MAX_PATH_LEN],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct BindEvent {
    pub _type: EventType,
    pub pid: u32,
    pub ip: [u8; 16], // Allow only IPv4
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ConnectEvent {
    pub _type: EventType,
    pub pid: u32,
    pub ip: [u8; 16], // Allow only IPv4
}