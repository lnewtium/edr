#![no_std]
#![no_main]

use aya_ebpf::helpers::{bpf_probe_read_user, bpf_probe_read_user_str_bytes};
use aya_ebpf::{macros::{map, tracepoint}, maps::ring_buf::RingBuf, programs::TracePointContext, EbpfContext};
use edr_common::{BindEvent, ConnectEvent, EventType, ExecEvent, OpenEvent, MAX_ARGS};

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0);

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn execve_trace(ctx: TracePointContext) -> u32 {
    let mut buf = match EVENTS.reserve::<ExecEvent>(0) {
        Some(b) => b,
        None => return 0,
    };
    // Layout according to format file of sys_enter_execve (kernel 5.10–6.12+)
    // offset  0–15  = common fields + __syscall_nr
    //        16     = const char *path
    //        24     = const char *const *argv
    //        32     = const char *const *envp

    let filename_ptr = unsafe { ctx.read_at::<*const u8>(16usize).unwrap_or_default() };
    let argv_ptr_ptr = unsafe { ctx.read_at::<*const *const u8>(24usize).unwrap_or_default() };

    let event = match unsafe {buf.as_mut_ptr().as_mut() } {
        Some(b) => b,
        None => {
            buf.discard(0);
            return 0;
        }
    };

    event._type = EventType::Exec;
    event.pid = ctx.pid();
    event.argc = 0;

    if let Err(_) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) } {
        buf.discard(0);
        return 0;
    }

    // Read up to MAX_ARGS arguments
    for i in 0..MAX_ARGS {
        let arg_ptr = match unsafe { bpf_probe_read_user::<*const u8>(argv_ptr_ptr.add(i)) } {
            Ok(b) => b,
            Err(_) => {
                buf.discard(0);
                return 0;
            }
        };
        if arg_ptr.is_null()
        {
            break;
        }

        match unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut event.args[i]) } {
            Ok(_) => {
                event.argc += 1;
            }
            Err(_) => {
                buf.discard(0);
                return 0;
            },
        }
    }
    buf.submit(0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_open")]
pub fn open_trace(ctx: TracePointContext) -> u32 {
    let mut buf = match EVENTS.reserve::<OpenEvent>(0) {
        Some(b) => b,
        None => return 0,
    };
    // Layout according to format file of sys_enter_open
    // offset  0–15  = common fields + __syscall_nr
    //        16     = const char *filename

    let filename_ptr = unsafe { ctx.read_at::<*const u8>(16usize).unwrap_or_default() };

    let event = match unsafe { buf.as_mut_ptr().as_mut() } {
        Some(b) => b,
        None => {
            buf.discard(0);
            return 0;
        }
    };

    event._type = EventType::Open;
    event.pid = ctx.pid();

    if let Err(_) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) } {
        buf.discard(0);
        return 0;
    }

    buf.submit(0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_bind")]
pub fn bind_trace(ctx: TracePointContext) -> u32 {
    let mut buf = match EVENTS.reserve::<BindEvent>(0) {
        Some(b) => b,
        None => return 0,
    };
    // Layout according to format file of sys_enter_bind
    // offset  0–15  = common fields + __syscall_nr
    //        16     = int sockfd
    //        24     = struct sockaddr *addr

    let addr_ptr = unsafe { ctx.read_at::<*const u8>(24usize).unwrap_or_default() };

    let event = match unsafe { buf.as_mut_ptr().as_mut() } {
        Some(b) => b,
        None => {
            buf.discard(0);
            return 0;
        }
    };

    event._type = EventType::Bind;
    event.pid = ctx.pid();

    if let Err(_) = unsafe { bpf_probe_read_user::<[u8; 16]>(addr_ptr as *const [u8; 16]) } {
        buf.discard(0);
        return 0;
    }

    buf.submit(0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn connect_trace(ctx: TracePointContext) -> u32 {
    let mut buf = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(b) => b,
        None => return 0,
    };
    // Layout according to format file of sys_enter_connect
    // offset  0–15  = common fields + __syscall_nr
    //        16     = int sockfd
    //        24     = struct sockaddr *addr

    let addr_ptr = unsafe { ctx.read_at::<*const u8>(24usize).unwrap_or_default() };

    let event = match unsafe { buf.as_mut_ptr().as_mut() } {
        Some(b) => b,
        None => {
            buf.discard(0);
            return 0;
        }
    };

    event._type = EventType::Connect;
    event.pid = ctx.pid();

    if let Err(_) = unsafe { bpf_probe_read_user::<[u8; 16]>(addr_ptr as *const [u8; 16]) } {
        buf.discard(0);
        return 0;
    }

    buf.submit(0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}