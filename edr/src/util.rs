use std::{fs, io};
use std::path::PathBuf;
use log::debug;

pub fn elf_path_from_pid(pid: u32) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/{}/exe", pid))
}

pub fn memlock() {
    // Increase memlock limit (required for eBPF)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("Failed to remove limit on locked memory: ret = {}", ret);
    }
}