#![no_std]

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub ipv4_destination: u32,
    pub action: XdpAction,
    pub packet_type: PacketType,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    TCP,
    UDP,
    ICMP,
    UNKNOW,
}

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum XdpAction {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
