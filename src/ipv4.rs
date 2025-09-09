use std::net::Ipv4Addr;
use crate::{
    util::checksum,
    tcp::TcpPacket,
    udp::UdpPacket
};

/// Next Level Packet from IPv4 Packet payload
pub enum Ipv4NextLevelPacket {
    Tcp(TcpPacket),
    Udp(UdpPacket)
}

/// IPv4 Option Class
/// Takes up 2nd and 3rd bits of an IPv4 Option
pub enum Ipv4OptionClass {
    /// 0b00
    Control,
    /// 0b10
    Debug,
    /// 0b01 if false
    /// 0b11 if true
    Reserved(bool)
}
impl Ipv4OptionClass {
    /// Construct a new IPv4 Option Class from bits
    /// Argument should be only 0, 1, 2 or 3
    pub fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Ipv4OptionClass::Control,
            1 => Ipv4OptionClass::Reserved(false),
            2 => Ipv4OptionClass::Debug,
            3 => Ipv4OptionClass::Reserved(true),
            _ => panic!("Ipv4OptionClass can be only 0, 1, 2 and 3!")
        }
    }
    /// Converts IPv4 Option Class to bits
    /// Returning an 0b0000_00XX pattern byte
    pub fn to_bits(&self) -> u8 {
        match self {
            Self::Control => {0}
            Self::Debug => {2}
            Self::Reserved(v) => {
                if *v {3}
                else {1}
            }
        }
    }
}

/// IPv4 Packet Option struct for `Ipv4Packet`
/// IPv4 Option are consist of:
///   1. 1 bit Copy flag
///   2. 2 bits Option Class
///   3. 5 bits Option Type Number
///   4. 1 byte length in bytes
///   5. N bytes data
pub struct Ipv4Option {
    /// `copy` flag for IPv4 Option
    pub copy: bool,
    /// IPv4 Option Class one of:
    ///   1. Control 0b00 | 0
    ///   2. Debug 0b10 | 2
    ///   3. Reserved(false) 0b01 | 1
    ///   4. Reserved(true) 0b11 | 3
    pub class: Ipv4OptionClass,
    /// One of IPv4 Option type numbers
    pub number: u8,
    /// Total length of option
    pub length: u8,
    /// Option Data
    pub data: Vec<u8>
}
impl Ipv4Option {
    /// Constructs an empty `Ipv4Option`
    pub fn new() -> Self {
        Self {
            copy: false,
            class: Ipv4OptionClass::Control,
            number: 0,
            length: 0,
            data: Vec::new()
        }
    }
    /// Constructs `Ipv4Option` from bytes
    /// Note that this method is not detecting where option starts and where ends
    /// This method **is not parsing options**, this method **exclusively constructs an one option**
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            copy: (bytes[0] & 0x80) != 0,
            class: Ipv4OptionClass::from_bits((bytes[0] & 0x60) >> 5),
            number: bytes[0] & 31,
            length: bytes[1],
            data: bytes[2..].to_vec()
        }
    }
    /// Converts option to bytes without padding
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut option = vec![0u8; 2];
        option[0] = (self.copy as u8) << 7;
        option[0] |= self.class.to_bits() << 5;
        option[0] |= self.number & 0x1F;
        option[1] = self.length;
        option.append(&mut self.data.clone());
        option
    }
    /// Recalculates `length` field of option base on data len
    pub fn recalculate_length(&mut self) -> () {
        self.length = self.data.len() as u8;
    }
}

pub struct Ipv4Packet {
    /// Ipv4 Header length of packet in bytes
    pub header_len: u8,
    /// Type of Service
    pub tos: u8,
    /// Total length of packet in bytes
    pub total_len: u16,
    /// Packet identification number
    pub id: u16,
    /// `dont_fragment` flag
    /// This flag means that packet shouldn't be fragmented
    pub dont_fragment: bool,
    /// `more_fragment` flag
    /// This flag means that packet has next packet fragment
    /// If packet wasn't fragmented or this is last fragment, this flag will be `false`
    pub more_fragments: bool,
    /// That field indicates the position of a fragment relative to the beginning of the original unfragmented IP Packet payload
    pub fragment_offset: u16,
    /// Time to Live
    /// On each router that this packet passes through, this field is decreased by 1
    /// When the value reaches 0, this packet is discarded
    pub ttl: u8,
    /// Next Level Packet protocol, i.e. 6 for TCP, 17 for UDP, etc.
    pub protocol: u8,
    /// Header checksum of this packet
    /// Note that this checksum affects only header, payload remains untouched
    pub checksum: u16,
    /// Source IPv4 address
    pub source: Ipv4Addr,
    /// Destination IPv4 address
    pub destination: Ipv4Addr,
    /// IPv4 Options
    pub options: Vec<Ipv4Option>,
    /// Packet Data
    pub payload: Vec<u8>
}
impl Ipv4Packet {
    /// Constructs an empty `Ipv4Packet`
    pub fn new() -> Self {
        Self {
            header_len: 0,
            tos: 0,
            total_len: 0,
            id: 0,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 0,
            protocol: 0,
            checksum: 0,
            source: Ipv4Addr::from_bits(0),
            destination: Ipv4Addr::from_bits(0),
            options: Vec::new(),
            payload: Vec::new()
        }
    }
    /// Constructs `Ipv4Packet` from existing packet bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if (bytes[0] >> 4) != 4 {
            panic!("Its not an Ipv4 packet!");
        }
        if bytes.len() < 20 {
            panic!("Length of bytes is less than 20!");
        }
        let mut packet: Self = Self::new();
        packet.header_len = (bytes[0] & 0xF) * 4;
        packet.tos = bytes[1];
        packet.total_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        packet.id = u16::from_be_bytes([bytes[4], bytes[5]]);
        packet.dont_fragment = (bytes[6] & 64) != 0;
        packet.more_fragments = (bytes[6] & 32) != 0;
        packet.fragment_offset = u16::from_be_bytes([bytes[6] & 31, bytes[7]]) * 8;
        packet.ttl = bytes[8];
        packet.protocol = bytes[9];
        packet.checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        packet.source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        packet.destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        if packet.header_len > 20 {
            let mut i = 20usize;
            while i < packet.header_len as usize {
                if bytes[i] == 0 {break;}
                if bytes[i] == 1 {
                    i += 1;
                    continue;
                }
                packet.options.push(Ipv4Option::from_bytes(&bytes[i..i + 2 + bytes[i + 1] as usize]));
                i += bytes[i + 1] as usize + 2;
            }
        }
        packet.payload = bytes[packet.header_len as usize..].to_vec();
        packet
    }
    /// Converting **only header** of packet to bytes
    pub fn header_to_bytes(&self) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 4 << 4;
        packet[0] |= (self.header_len / 4) & 0xF;
        packet[1] = self.tos;
        packet[2..=3].copy_from_slice(&self.total_len.to_be_bytes());
        packet[4..=5].copy_from_slice(&self.id.to_be_bytes());
        packet[6] = (self.dont_fragment as u8) << 6;
        packet[6] |= (self.more_fragments as u8) << 5;
        let fragment_offset = (self.fragment_offset / 8).to_be_bytes();
        packet[6] |= fragment_offset[0];
        packet[7] = fragment_offset[1];
        packet[8] = self.ttl;
        packet[9] = self.protocol;
        packet[10..=11].copy_from_slice(&self.checksum.to_be_bytes());
        packet[12..=15].copy_from_slice(&self.source.octets());
        packet[16..19].copy_from_slice(&self.destination.octets());
        for option in self.options.iter() {
            packet.append(&mut option.to_bytes());
        }
        let padding = packet.len() % 4;
        if padding != 0 {
            packet.append(&mut vec![1; 4 - padding - 1]);
            packet.push(0);
        }
        packet
    }
    /// Converting **full** packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.header_to_bytes();
        packet.append(&mut self.payload.clone());
        packet
    }
    /// Recalculates `header_len` and `total_len` fields in `Ipv4Packet`
    pub fn recalculate_lengths(&mut self) -> () {
        let header = self.header_to_bytes().len();
        self.header_len = header as u8;
        self.total_len = header as u16 + self.payload.len() as u16;
    }
    /// Recalculates `checksum` field in `Ipv4Packet`
    /// Note that this checksum affects only header, payload remains untouched
    pub fn recalculate_checksum(&mut self) -> () {
        self.checksum = checksum(self.header_to_bytes());
    }
    /// Gives a next level packet, i.e. if protocol is TCP -> gives TcpPacket, if protocol is UDP -> gives UdpPacket, etc.
    pub fn get_next_level_packet(&self) -> Ipv4NextLevelPacket {
        match self.protocol {
            6 => Ipv4NextLevelPacket::Tcp(TcpPacket::from_bytes(&self.payload.clone())),
            17 => Ipv4NextLevelPacket::Udp(UdpPacket::from_bytes(&self.payload.clone())),
            _ => unimplemented!()
        }
    }
}