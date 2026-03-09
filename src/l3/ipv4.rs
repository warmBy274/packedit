use core::net::Ipv4Addr;
use crate::util::{Serializable, Deserializable, DeserializeError, checksum};
pub use super::{DscpType, EcnType};

/// IPv4 Option Class
/// Takes up 2nd and 3rd bits of an IPv4 Option
#[derive(Debug, Clone)]
pub enum Ipv4OptionClass {
    /// 0b00
    Control,
    /// 0b01
    Reserved1,
    /// 0b10
    Debug,
    /// 0b11
    Reserved2
}
impl Serializable for Ipv4OptionClass {
    /// Converts IPv4 Option Class to bits
    /// Returning an 0b0000_00XX pattern byte
    fn serialize(self) -> Vec<u8> {
        vec![self as u8]
    }
}
impl Deserializable for Ipv4OptionClass {
    /// Construct a new IPv4 Option Class from bits
    /// Argument should be only 0, 1, 2 or 3
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() == 0 {return Err(DeserializeError::WrongDataLength);}
        match bytes[0] {
            0 => Ok(Self::Control),
            1 => Ok(Self::Reserved1),
            2 => Ok(Self::Debug),
            3 => Ok(Self::Reserved2),
            _ => Err(DeserializeError::WrongData)
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
#[derive(Debug, Clone)]
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
    pub type_number: u8,
    /// Option Data
    pub data: Vec<u8>
}
impl Ipv4Option {
    /// Constructs an empty `Ipv4Option` with 'copy = false', `Ipv4OptionClass::Control`, `type_number = 0` and empty data
    pub fn new() -> Self {
        Self {
            copy: false,
            class: Ipv4OptionClass::Control,
            type_number: 0,
            data: Vec::new()
        }
    }
}
impl Serializable for Ipv4Option {
    /// Converts option to bytes without padding
    fn serialize(mut self) -> Vec<u8> {
        let mut result = vec![0u8; 2];
        result[0] = (self.copy as u8) << 7;
        result[0] |= self.class.serialize()[0] << 5;
        result[0] |= self.type_number & 31;
        result[1] = self.data.len() as u8 + 2;
        result.append(&mut self.data);
        result
    }
}
impl Deserializable for Ipv4Option {
    /// Constructs `Ipv4Option` from bytes
    /// Note that this method is know where option ends
    /// So, dont worry about it
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 3 {return Err(DeserializeError::WrongDataLength);}
        Ok(Self {
            copy: (bytes[0] & 128) != 0,
            class: Ipv4OptionClass::deserialize(&[(bytes[0] & 96) >> 5])?,
            type_number: bytes[0] & 31,
            data: bytes[2..bytes[1] as usize].to_vec()
        })
    }
}

/// Struct for oridinary IPv4 Packet
/// You can construct it from scratch with `Ipv4Packet::new()` and consistently editing
/// Or construct from existing packet bytes with `Ipv4Packet::from_bytes()`
/// All `u16` fields of this packet **are not in big-endian order**
/// All `u16` fields of this packet **are in native order**
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    /// Differentiated Services Code Point
    pub dscp: DscpType,
    /// Explicit Congestion Notification
    pub ecn: EcnType,
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
            dscp: DscpType::BE,
            ecn: EcnType::NotECT,
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
    /// Recalculates `checksum` field in `Ipv4Packet`
    /// Note that this checksum affects only header, payload remains untouched
    pub fn recalculate_checksum(&mut self) -> () {
        let mut serialized = self.clone_header().serialize();
        let length = serialized.len() + self.payload.len();
        serialized[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        self.checksum = checksum(serialized);
    }
    pub fn clone_header(&self) -> Self {
        Self {
            payload: Vec::new(),
            ..self.clone()
        }
    }
}
impl Serializable for Ipv4Packet {
    fn serialize(mut self) -> Vec<u8> {
        let mut result = vec![0u8; 20];
        result[0] = 4 << 4;
        result[1] = self.ecn.serialize()[0];
        result[1] |= self.dscp.serialize()[0] << 2;
        result[4..6].copy_from_slice(&self.id.to_be_bytes());
        result[6] = (self.dont_fragment as u8) << 6;
        result[6] |= (self.more_fragments as u8) << 5;
        let fragment_offset = (self.fragment_offset / 8).to_be_bytes();
        result[6] |= fragment_offset[0];
        result[7] = fragment_offset[1];
        result[8] = self.ttl;
        result[9] = self.protocol;
        result[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        result[12..16].copy_from_slice(&self.source.octets());
        result[16..20].copy_from_slice(&self.destination.octets());
        for option in self.options {
            result.append(&mut option.serialize());
        }
        let padding = 4 - result.len() % 4;
        if padding != 0 {
            result.append(&mut vec![1; 4 - padding - 1]);
            result.push(0);
        }
        result[0] |= (result.len() / 4) as u8 & 0xF;
        result.append(&mut self.payload);
        let length = result.len();
        result[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        result
    }
}
impl Deserializable for Ipv4Packet {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 20 {return Err(DeserializeError::WrongDataLength);}
        if (bytes[0] >> 4) != 4 {return Err(DeserializeError::WrongData);}
        let mut packet = Self::new();
        let header_len = (bytes[0] & 15) * 4;
        packet.dscp = DscpType::deserialize(&[bytes[1] >> 2])?;
        packet.ecn = EcnType::deserialize(&[bytes[1] & 3])?;
        packet.id = u16::from_be_bytes([bytes[4], bytes[5]]);
        packet.dont_fragment = (bytes[6] & 64) != 0;
        packet.more_fragments = (bytes[6] & 32) != 0;
        packet.fragment_offset = u16::from_be_bytes([bytes[6] & 31, bytes[7]]) * 8;
        packet.ttl = bytes[8];
        packet.protocol = bytes[9];
        packet.checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        packet.source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        packet.destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        if header_len > 20 {
            let mut i = 20usize;
            while i < header_len as usize {
                if bytes[i] == 0 || bytes[i] == 1 {
                    i += 1;
                    continue;
                }
                packet.options.push(Ipv4Option::deserialize(&bytes[i..])?);
                i += bytes[i + 1] as usize;
            }
        }
        packet.payload = bytes[header_len as usize..].to_vec();
        Ok(packet)
    }
}