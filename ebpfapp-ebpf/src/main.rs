#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};

#[xdp(name="ebpfapp")]
pub fn ebpfapp(ctx: XdpContext) -> u32 {
    match unsafe { try_ebpfapp(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_ebpfapp(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
