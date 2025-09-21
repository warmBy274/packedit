use crate::util::Packet;
#[cfg(feature = "legacy-arp")]
use crate::util::{HardwareAddress, ProtocolAddress};
#[cfg(not(feature = "legacy-arp"))]
use {
    crate::util::MacAddress,
    std::net::Ipv4Addr
};

#[derive(Debug, Clone)]
pub enum ArpOperation {
    Request,
    Reply,
    RarpRequest,
    RarpReply,
    #[cfg(feature = "legacy-arp")]
    InArpRequest,
    #[cfg(feature = "legacy-arp")]
    InArpReply
}
impl ArpOperation {
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            3 => Self::RarpRequest,
            4 => Self::RarpReply,
            #[cfg(feature = "legacy-arp")]
            8 => Self::InArpRequest,
            #[cfg(feature = "legacy-arp")]
            9 => Self::InArpReply,
            #[cfg(feature = "legacy-arp")]
            _ => panic!("Value can be only 1, 2, 3, 4, 8, 9!"),
            #[cfg(not(feature = "legacy-arp"))]
            _ => panic!("Value can be only 1, 2, 3, 4!")
        }
    }
    pub fn to_value(&self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::RarpRequest => 3,
            Self::RarpReply => 4,
            #[cfg(feature = "legacy-arp")]
            Self::InArpRequest => 8,
            #[cfg(feature = "legacy-arp")]
            Self::InArpReply => 9
        }
    }
}

#[cfg(feature = "legacy-arp")]
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_addr_len: u8,
    pub protocol_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hardware_addr: HardwareAddress,
    pub sender_protocol_addr: ProtocolAddress,
    pub target_hardware_addr: HardwareAddress,
    pub target_protocol_addr: ProtocolAddress,
}
#[cfg(not(feature = "legacy-arp"))]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Addr
}
impl ArpPacket {
    /// Constructs an empty `ArpPacket`
    #[cfg(feature = "legacy-arp")]
    pub fn new() -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_addr_len: 6,
            protocol_addr_len: 4,
            operation: ArpOperation::Request,
            sender_hardware_addr: HardwareAddress::None,
            sender_protocol_addr: ProtocolAddress::None,
            target_hardware_addr: HardwareAddress::None,
            target_protocol_addr: ProtocolAddress::None
        }
    }
    /// Constructs an empty `ArpPacket`
    #[cfg(not(feature = "legacy-arp"))]
    pub fn new() -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            operation: ArpOperation::Request,
            sender_mac: MacAddress::new(),
            sender_ip: Ipv4Addr::new(0, 0, 0, 0),
            target_mac: MacAddress::new(),
            target_ip: Ipv4Addr::new(0, 0, 0, 0)
        }
    }
}
impl Packet for ArpPacket {
    /// Constructs `ArpPacket` from existing packet bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut packet = Self::new();
        packet.hardware_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        packet.protocol_type = u16::from_be_bytes([bytes[2], bytes[3]]);
        packet.operation = ArpOperation::from_value(u16::from_be_bytes([bytes[6], bytes[7]]));
        #[cfg(feature = "legacy-arp")]
        {
            packet.hardware_addr_len = bytes[4];
            packet.protocol_addr_len = bytes[5];
            unimplemented!();
            // Parse hardware and protocol types here
            // Parse addresses here
        }
        #[cfg(not(feature = "legacy-arp"))]
        {
            if bytes[4] != 6 {
                panic!("Hardware Address Length in normal ARP packet is equal to 6, use 'legacy-arp' feature to parse more ARP Packet types");
            }
            if bytes[5] != 4 {
                panic!("Protocol Address Length in normal ARP packet is equal to 6, use 'legacy-arp' feature to parse more ARP Packet types");
            }
            packet.sender_mac = MacAddress::from_slice(&bytes[8..=13]);
            packet.sender_ip = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
            packet.target_mac = MacAddress::from_slice(&bytes[18..=23]);
            packet.target_ip = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
        }
        packet
    }
    /// Converting **full** packet to bytes
    /// Note that in context of `ArpPacket` methods `header_to_bytes()` and `to_bytes()` are equal, because ARP Packet doesn't have payload
    fn header_to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::<u8>::with_capacity(8);
        packet.append(&mut self.hardware_type.to_be_bytes().to_vec());
        packet.append(&mut self.protocol_type.to_be_bytes().to_vec());
        packet.push(0);
        packet.push(0);
        packet.append(&mut self.operation.to_value().to_be_bytes().to_vec());
        #[cfg(feature = "legacy-arp")]
        {
            packet[4] = self.hardware_addr_len;
            packet[5] = self.protocol_addr_len;
            // Finish it
        }
        #[cfg(not(feature = "legacy-arp"))]
        {
            packet[4] = 6;
            packet[5] = 4;
            packet.append(&mut self.sender_mac.to_bytes().to_vec());
            packet.append(&mut self.sender_ip.octets().to_vec());
            packet.append(&mut self.target_mac.to_bytes().to_vec());
            packet.append(&mut self.target_ip.octets().to_vec());
        }
        packet
    }
    /// This method is equal to `header_to_bytes()` in context of `ArpPacket`
    fn to_bytes(&self) -> Vec<u8> {
        self.header_to_bytes()
    }
}