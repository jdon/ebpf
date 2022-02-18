#![no_std]
#![no_main]
mod bindings;
use core::mem;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use bindings::{ethhdr, iphdr};
use ebpfapp_common::PacketLog;
use memoffset::offset_of;

#[inline(always)] // Inline due to limited support for function calls in ebpf programs
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let destination =
        u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    let prot_be = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? });

    // let protocol_type = match protoctol {
    //     IPPROTO_TCP => DataType::TCP,
    //     IPPROTO_UDP => DataType::UDP,
    //     IPPROTO_ICMP => DataType::ICMP,
    //     _ => DataType::UNKNOW
    // };

    let log_entry = PacketLog {
        ipv4_address: source,
        action: xdp_action::XDP_PASS,
        ipv4_destination: destination,
        packet_type: prot_be,
    };
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(xdp_action::XDP_PASS)
}
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1034, 0);

#[xdp(name = "ebpfapp")]
pub fn ebpfapp(ctx: XdpContext) -> u32 {
    match { try_xdp_firewall(ctx) } {
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
