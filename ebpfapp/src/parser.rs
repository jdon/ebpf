use bytes::BytesMut;
use ebpfapp_common::{PacketType, XdpAction};
use std::net::Ipv4Addr;

pub struct Packet {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub action: XdpAction,
    pub packet_type: PacketType,
}

//New type for to_str
pub trait ParserToString {
    fn to_str(&self) -> &'static str;
}

impl ParserToString for PacketType {
    fn to_str(&self) -> &'static str {
        match self {
            ebpfapp_common::PacketType::TCP => "TCP",
            ebpfapp_common::PacketType::UDP => "UDP",
            ebpfapp_common::PacketType::ICMP => "ICMP",
            ebpfapp_common::PacketType::UNKNOW => "UNKNOW",
        }
    }
}

impl ParserToString for XdpAction {
    fn to_str(&self) -> &'static str {
        match self {
            XdpAction::ABORTED => "ABORTED",
            XdpAction::DROP => "DROP",
            XdpAction::PASS => "PASS",
            XdpAction::TX => "TX",
            XdpAction::REDIRECT => "REDIRECT",
        }
    }
}

pub fn parse_buf(buf: &mut BytesMut) -> Packet {
    let ptr = buf.as_ptr().cast::<ebpfapp_common::PacketLog>();
    let data = unsafe { ptr.read_unaligned() };
    let src_addr = Ipv4Addr::from(data.ipv4_address);
    let dst_addr = Ipv4Addr::from(data.ipv4_destination);
    Packet {
        source: src_addr,
        destination: dst_addr,
        action: data.action,
        packet_type: data.packet_type,
    }
}
