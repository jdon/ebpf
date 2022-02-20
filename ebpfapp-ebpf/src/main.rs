#![no_std]
#![no_main]
mod bindings;
use core::{mem, ptr::addr_of};

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use bindings::{ethhdr, iphdr};
use ebpfapp_common::{PacketLog, PacketType, XdpAction};
use memoffset::offset_of;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[inline(always)] // Inline due to limited support for function calls in ebpf programs
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Needed so that bpf verifier can verify data reads are valid
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub struct IPV4 {
    source: u32,
    destination: u32,
    protocol: PacketType,
}

#[inline(always)]
fn parse_ipv4(ctx: &XdpContext) -> Result<IPV4, ()> {
    let source = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let destination =
        u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    let protocol_type =
        match u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? }) {
            IPPROTO_TCP => PacketType::TCP,
            IPPROTO_UDP => PacketType::UDP,
            IPPROTO_ICMP => PacketType::ICMP,
            _ => PacketType::UNKNOW,
        };

    Ok(IPV4 {
        source,
        destination,
        protocol: protocol_type,
    })
}

#[inline(always)]
fn is_ipv4(ctx: &XdpContext) -> Result<bool, ()> {
    // Get protocol type of ethernet frame
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    // Check if it's ipv4, if isn't then allow it.
    if h_proto == ETH_P_IP {
        return Ok(true);
    }
    Ok(false)
}

#[inline(always)]
fn generate_log(parsed_ipv4: IPV4, action: XdpAction) -> PacketLog {
    PacketLog {
        ipv4_address: parsed_ipv4.source,
        action,
        ipv4_destination: parsed_ipv4.destination,
        packet_type: parsed_ipv4.protocol,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let is_ipv4 = is_ipv4(&ctx)?;
    if is_ipv4 == false {
        return Ok(xdp_action::XDP_PASS);
    }
    let parsed_ipv4 = parse_ipv4(&ctx)?;

    if let Some(action) = unsafe { ACTION_LIST.get(&parsed_ipv4.source) } {
        match action {
            XdpAction::PASS => {}
            _ => {
                let log_entry = generate_log(parsed_ipv4, *action);
                unsafe { EVENTS.output(&ctx, &log_entry, 0) };
            }
        };

        return Ok(*action as u32);
    }

    let log_entry = generate_log(parsed_ipv4, XdpAction::PASS);
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1034, 0);

#[map(name = "ACTION_LIST")]
static mut ACTION_LIST: HashMap<u32, XdpAction> = HashMap::with_max_entries(1024, 0);

#[xdp(name = "ebpfapp")]
pub fn ebpfapp(ctx: XdpContext) -> u32 {
    match { try_xdp_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
