use crate::util::Packet;
#[cfg(not(feature = "advanced-arp"))]
use {
    crate::util::MacAddress,
    std::net::Ipv4Addr
};

/// Just ARP Packet `operation` field, can be `Request` or `Reply`, or something else if you using other ARP types, such as Reverse ARP(RARP)
#[derive(Debug, Clone)]
pub enum ArpOperation {
    Request,
    Reply,
    RarpRequest,
    RarpReply,
    #[cfg(feature = "advanced-arp")]
    InArpRequest,
    #[cfg(feature = "advanced-arp")]
    InArpReply,
    #[cfg(feature = "advanced-arp")]
    Other(u16)
}
impl ArpOperation {
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            3 => Self::RarpRequest,
            4 => Self::RarpReply,
            #[cfg(feature = "advanced-arp")]
            8 => Self::InArpRequest,
            #[cfg(feature = "advanced-arp")]
            9 => Self::InArpReply,
            #[cfg(feature = "advanced-arp")]
            _ => Self::Other(value),
            #[cfg(not(feature = "advanced-arp"))]
            _ => panic!("Value can be only 1, 2, 3, 4!")
        }
    }
    pub fn to_value(&self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::RarpRequest => 3,
            Self::RarpReply => 4,
            #[cfg(feature = "advanced-arp")]
            Self::InArpRequest => 8,
            #[cfg(feature = "advanced-arp")]
            Self::InArpReply => 9,
            #[cfg(feature = "advanced-arp")]
            Self::Other(value) => *value
        }
    }
}

/// Advanced ARP Packet, can resolve many legacy ARP Packets, such as AX25, ATM and other, due to the presence of vectors instead of ready-made structs like `Ipv4Addr` and `MacAddress`
#[cfg(feature = "advanced-arp")]
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_addr_len: u8,
    pub protocol_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hardware_addr: Vec<u8>,
    pub sender_protocol_addr: Vec<u8>,
    pub target_hardware_addr: Vec<u8>,
    pub target_protocol_addr: Vec<u8>
}
/// Normal ARP Packet, containing sender and target MAC and IP Addresses, with `hardware_addr_len = 6`, `protocol_addr_len = 4`, `hardware_type = 1` and `protocol_type = 0x0800(2048)`
#[cfg(not(feature = "advanced-arp"))]
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Addr
}
impl ArpPacket {
    /// Constructs an empty `ArpPacket`
    #[cfg(feature = "advanced-arp")]
    pub fn new() -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_addr_len: 6,
            protocol_addr_len: 4,
            operation: ArpOperation::Request,
            sender_hardware_addr: Vec::new(),
            sender_protocol_addr: Vec::new(),
            target_hardware_addr: Vec::new(),
            target_protocol_addr: Vec::new()
        }
    }
    /// Constructs an empty `ArpPacket`
    #[cfg(not(feature = "advanced-arp"))]
    pub fn new() -> Self {
        Self {
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
        packet.operation = ArpOperation::from_value(u16::from_be_bytes([bytes[6], bytes[7]]));
        #[cfg(feature = "advanced-arp")]
        {
            packet.hardware_type = u16::from_be_bytes([bytes[0], bytes[1]]);
            packet.protocol_type = u16::from_be_bytes([bytes[2], bytes[3]]);
            packet.hardware_addr_len = bytes[4];
            packet.protocol_addr_len = bytes[5];
            packet.sender_hardware_addr = bytes[8..8 + packet.hardware_addr_len as usize].to_vec();
            packet.sender_protocol_addr = bytes[8 + packet.hardware_addr_len as usize..(8 + packet.hardware_addr_len + packet.protocol_addr_len) as usize].to_vec();
            packet.target_hardware_addr = bytes[(8 + packet.hardware_addr_len + packet.protocol_addr_len) as usize..(8 + 2 * packet.hardware_addr_len + packet.protocol_addr_len) as usize].to_vec();
            packet.target_protocol_addr = bytes[(8 + 2 * packet.hardware_addr_len + packet.protocol_addr_len) as usize..(8 + 2 * packet.hardware_addr_len + 2 * packet.protocol_addr_len) as usize].to_vec();
        }
        #[cfg(not(feature = "advanced-arp"))]
        {
            if u16::from_be_bytes([bytes[0], bytes[1]]) != 1 {
                panic!("Hardware type must be only 1, if you need to parse other hardware types, use 'advanced-arp' feature");
            }
            if u16::from_be_bytes([bytes[2], bytes[3]]) != 0x0800 {
                panic!("Protocol type must be only 0x0800(2048), if you need to parse other protocol types, use 'advanced-arp' feature");
            }
            if bytes[4] != 6 {
                panic!("Hardware Address Length in normal ARP packet is equal to 6, use 'advanced-arp' feature to parse more ARP Packet types");
            }
            if bytes[5] != 4 {
                panic!("Protocol Address Length in normal ARP packet is equal to 6, use 'advanced-arp' feature to parse more ARP Packet types");
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
        let mut packet = vec![0u8; 8];
        packet[6..=7].copy_from_slice(&self.operation.to_value().to_be_bytes());
        #[cfg(feature = "advanced-arp")]
        {
            packet[0..=1].copy_from_slice(&self.hardware_type.to_be_bytes());
            packet[2..=3].copy_from_slice(&self.protocol_type.to_be_bytes());
            packet[4] = self.hardware_addr_len;
            packet[5] = self.protocol_addr_len;
            packet.append(&mut self.sender_hardware_addr.clone());
            packet.append(&mut self.sender_protocol_addr.clone());
            packet.append(&mut self.target_hardware_addr.clone());
            packet.append(&mut self.target_protocol_addr.clone());
        }
        #[cfg(not(feature = "advanced-arp"))]
        {
            packet[0] = 0;
            packet[1] = 1;
            packet[2] = 8;
            packet[3] = 0;
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