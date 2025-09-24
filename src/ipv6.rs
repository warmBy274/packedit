use std::net::Ipv6Addr;
use crate::{
    util::Packet,
    tcp::TcpPacket,
    udp::UdpPacket
};
pub use crate::util::{DscpType, EcnType};

/// Next Level Packet from IPv6 Packet payload
#[derive(Debug, Clone)]
pub enum Ipv6NextLevelPacket {
    Tcp(TcpPacket),
    Udp(UdpPacket),
    Unimplemented(Vec<u8>)
}

#[derive(Debug, Clone)]
pub enum Ipv6ExtensionHeader {
    HopByHopOptions {
        next_header: u8,
        options: Vec<Ipv6Option>
    },
    Routing {
        next_header: u8,
        payload: Vec<u8>
    },
    Fragment {
        next_header: u8,
        payload: Vec<u8>
    },
    DestinationOptions {
        next_header: u8,
        options: Vec<Ipv6Option>
    },
    Mobility {
        next_header: u8,
        payload: Vec<u8>
    }
}
impl Ipv6ExtensionHeader {
    /// Converts IPv6 Extension Header to bytes with calculating correct padding automatically
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::new();
        match self {
            Self::HopByHopOptions {next_header, options} => {
                header.push(*next_header);
                let mut option_bytes = Vec::new();
                for option in options.iter() {
                    option_bytes.append(&mut option.to_bytes());
                }
                header.push(((option_bytes.len() + 2) / 8 - 1) as u8);
                header.append(&mut option_bytes);
                let padding = header.len() % 8;
                if padding != 0 {
                    if 8 - padding == 1 {
                        header.push(0);
                    }
                    else {
                        header.push(1);
                        header.push((8 - padding - 2) as u8);
                        header.append(&mut vec![0u8; 8 - padding - 2]);
                    }
                }
            }
            Self::Routing {next_header, payload} => {
                header.push(*next_header);
                header.push(((payload.len() + 2) / 8 - 1) as u8);
                header.append(&mut payload.clone());
            }
            Self::Fragment {next_header, payload} => {
                header.push(*next_header);
                header.append(&mut payload.clone());
            }
            Self::DestinationOptions {next_header, options} => {
                header.push(*next_header);
                let mut option_bytes = Vec::new();
                for option in options.iter() {
                    option_bytes.append(&mut option.to_bytes());
                }
                header.push(((option_bytes.len() + 2) / 8 - 1) as u8);
                header.append(&mut option_bytes);
                let padding = 8 - header.len() % 8;
                if padding != 0 {
                    if 8 - padding == 1 {
                        header.push(0);
                    }
                    else {
                        header.push(1);
                        header.push((8 - padding - 2) as u8);
                        header.append(&mut vec![0u8; 8 - padding - 2]);
                    }
                }
            }
            Self::Mobility {next_header, payload} => {
                header.push(*next_header);
                header.push(((payload.len() + 2) / 8 - 1) as u8);
                header.append(&mut payload.clone());
                header.append(&mut vec![0u8; 8 - header.len() % 8]);
            }
        }
        header
    }
    pub fn get_type(&self) -> u8 {
        match self {
            Self::HopByHopOptions {next_header: _, options: _} => 0,
            Self::Routing {next_header: _, payload: _} => 43,
            Self::Fragment {next_header: _, payload: _} => 44,
            Self::DestinationOptions {next_header: _, options: _} => 60,
            Self::Mobility {next_header: _, payload: _} => 135
        }
    }
    pub fn get_next_header_type(&self) -> u8 {
        match self {
            Self::HopByHopOptions {next_header, options: _} => *next_header,
            Self::Routing {next_header, payload: _} => *next_header,
            Self::Fragment {next_header, payload: _} => *next_header,
            Self::DestinationOptions {next_header, options: _} => *next_header,
            Self::Mobility {next_header, payload: _} => *next_header
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Option {
    pub kind: u8,
    pub data: Vec<u8>
}
impl Ipv6Option {
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.kind == 0 {
            vec![0]
        }
        else {
            let mut option: Vec<u8> = vec![];
            option.push(self.kind);
            option.push(self.data.len() as u8);
            option.append(&mut self.data.clone());
            option
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    /// Differentiated Services Code Point
    pub dscp: DscpType,
    /// Explicit Congestion Notification
    pub ecn: EcnType,
    /// In fact, this field has to be 20 bits size, but rust dont allow this, so, just keep this in mind
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub extension_headers: Vec<Ipv6ExtensionHeader>,
    pub payload: Vec<u8>
}
impl Ipv6Packet {
    pub fn new() -> Self {
        Self {
            dscp: DscpType::CS0,
            ecn: EcnType::NotECT,
            flow_label: 0,
            payload_len: 0,
            next_header: 0,
            hop_limit: 0,
            source: Ipv6Addr::from_bits(0),
            destination: Ipv6Addr::from_bits(0),
            extension_headers: Vec::new(),
            payload: Vec::new()
        }
    }
    pub fn recalculate_length(&mut self) -> () {
        let mut length = self.payload.len() as u16;
        for header in self.extension_headers.iter() {
            length += header.to_bytes().len() as u16;
        }
        self.payload_len = length;
    }
    pub fn recalculate_next_header(&mut self) -> () {
        self.next_header = self.extension_headers[0].get_type();
    }
    pub fn recalculate_all(&mut self) -> () {
        self.recalculate_length();
        self.recalculate_next_header();
    }
    pub fn get_next_level_packet(&self) -> Ipv6NextLevelPacket {
        let protocol;
        if self.extension_headers.is_empty() {
            protocol = self.next_header;
        }
        else {
            protocol = self.extension_headers.last().unwrap().get_next_header_type();
        }
        match protocol {
            6 => Ipv6NextLevelPacket::Tcp(TcpPacket::from_bytes(self.payload.clone().as_slice())),
            17 => Ipv6NextLevelPacket::Udp(UdpPacket::from_bytes(self.payload.clone().as_slice())),
            _ => Ipv6NextLevelPacket::Unimplemented(self.payload.clone())
        }
    }
}
impl Packet for Ipv6Packet {
    fn from_bytes(bytes: &[u8]) -> Self {
        if (bytes[0] >> 4) != 6 {
            panic!("Its not an Ipv4 packet!");
        }
        if bytes.len() < 40 {
            panic!("Length of bytes is less than 40!");
        }
        let mut packet = Self::new();
        packet.dscp = DscpType::from_bits(((bytes[0] & 0xF) << 2) | ((bytes[1] & 192) >> 6));
        packet.ecn = EcnType::from_bits((bytes[1] & 48) >> 4);
        packet.flow_label = u32::from_be_bytes([0u8, bytes[1] & 0xF, bytes[2], bytes[3]]);
        packet.payload_len = u16::from_be_bytes([bytes[4], bytes[5]]);
        packet.next_header = bytes[6];
        packet.hop_limit = bytes[7];
        let mut source = [0u8; 16];
        source.copy_from_slice(&bytes[8..=23]);
        packet.source = Ipv6Addr::from_bits(u128::from_be_bytes(source));
        let mut destination = [0u8; 16];
        destination.copy_from_slice(&bytes[24..=39]);
        packet.destination = Ipv6Addr::from_bits(u128::from_be_bytes(destination));
        let mut next_header = bytes[6];
        let mut i = 40usize;
        loop {
            match next_header {
                0 => {
                    let length = (bytes[i + 1] as usize + 1) * 8 - 2;
                    let data = &bytes[i + 2..i + 2 + length];
                    let mut options: Vec<Ipv6Option> = Vec::new();
                    let mut j = 0usize;
                    while j < length {
                        if data[j] == 0 {
                            options.push(Ipv6Option {
                                kind: 0,
                                data: Vec::new()
                            });
                            j += 1;
                        }
                        else {
                            options.push(Ipv6Option {
                                kind: data[j],
                                data: data[j + 2..j + 2 + data[j + 1] as usize].to_vec()
                            });
                            j += 2 + data[j + 1] as usize;
                        }
                    }
                    packet.extension_headers.push(Ipv6ExtensionHeader::HopByHopOptions {
                        next_header: bytes[i],
                        options: options
                    });
                    next_header = bytes[i];
                    i += length + 2;
                }
                43 => {
                    let length = (bytes[i + 1] as usize + 1) * 8;
                    packet.extension_headers.push(Ipv6ExtensionHeader::Routing {
                        next_header: bytes[i],
                        payload: bytes[i + 2..i + length].to_vec()
                    });
                    next_header = bytes[i];
                    i += length;
                }
                44 => {
                    packet.extension_headers.push(Ipv6ExtensionHeader::Fragment {
                        next_header: bytes[i],
                        payload: bytes[i + 1..i + 8].to_vec()
                    });
                    next_header = bytes[i];
                    i += 8;
                }
                60 => {
                    let length = (bytes[i + 1] as usize + 1) * 8 - 2;
                    let data = &bytes[i + 2..i + 2 + length];
                    let mut  options: Vec<Ipv6Option> = Vec::new();
                    let mut j = 0usize;
                    while j < length {
                        if data[j] == 0 {
                            options.push(Ipv6Option {
                                kind: 0,
                                data: Vec::new()
                            });
                            j += 1;
                        }
                        else {
                            options.push(Ipv6Option {
                                kind: data[j],
                                data: data[j + 2..j + 2 + data[j + 1] as usize].to_vec()
                            });
                            j += 2 + data[j + 1] as usize;
                        }
                    }
                    packet.extension_headers.push(Ipv6ExtensionHeader::DestinationOptions {
                        next_header: bytes[i],
                        options: options
                    });
                    next_header = bytes[i];
                    i += length + 2;
                }
                135 => {
                    let length = (bytes[i + 1] as u16 + 1) * 8;
                    packet.extension_headers.push(Ipv6ExtensionHeader::Mobility {
                        next_header: bytes[i],
                        payload: bytes[i + 2..i + length as usize].to_vec()
                    });
                    next_header = bytes[i];
                    i += length as usize;
                }
                _ => {
                    packet.payload = bytes[i..].to_vec();
                    break;
                }
            }
        }
        packet
    }
    fn header_to_bytes(&self) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 6 << 4;
        let dscp = self.dscp.to_bits();
        packet[0] |= dscp >> 2;
        packet[1] = dscp << 6;
        packet[1] |= self.ecn.to_bits() << 4;
        let flow_label = self.flow_label.to_be_bytes();
        packet[1] |= flow_label[1] & 0xF;
        packet[2] = flow_label[2];
        packet[3] = flow_label[3];
        packet[4..=5].copy_from_slice(&self.payload_len.to_be_bytes());
        packet[6] = self.next_header;
        packet[7] = self.hop_limit;
        packet[8..=23].copy_from_slice(&self.source.octets());
        packet[24..=39].copy_from_slice(&self.destination.octets());
        for header in self.extension_headers.iter() {
            packet.append(&mut header.to_bytes());
        }
        packet
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.header_to_bytes();
        packet.append(&mut self.payload.clone());
        packet
    }
}