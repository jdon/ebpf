use bytes::BytesMut;
use ebpfapp_common::{PacketLog, PacketType};
use std::net::Ipv4Addr;

pub struct Packet {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub action: u32,
    pub packet_type: PacketType,
}

pub trait PacketToString {
    fn to_str(&self) -> &'static str;
}

impl PacketToString for PacketType {
    fn to_str(&self) -> &'static str {
        match self {
            ebpfapp_common::PacketType::TCP => "TCP",
            ebpfapp_common::PacketType::UDP => "UDP",
            ebpfapp_common::PacketType::ICMP => "ICMP",
            ebpfapp_common::PacketType::UNKNOW => "UNKNOW",
        }
    }
}

pub fn parse_buf(buf: &mut BytesMut) -> Packet {
    let ptr = buf.as_ptr() as *const PacketLog;
    let data = unsafe { ptr.read_unaligned() };
    let src_addr = Ipv4Addr::from(data.ipv4_address);
    let dst_addr = Ipv4Addr::from(data.ipv4_destination);
    let packet_type = data.packet_type.to_str();
    Packet {
        source: src_addr,
        destination: dst_addr,
        action: data.action,
        packet_type: data.packet_type,
    }
}
