#![no_std]

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub ipv4_destination: u32,
    pub action: u32,
    pub packet_type: PacketType,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PacketType {
    TCP,
    UDP,
    ICMP,
    UNKNOW,
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
