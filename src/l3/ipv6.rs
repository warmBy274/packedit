use core::net::Ipv6Addr;
use crate::util::{Deserializable, DeserializeError, Serializable};
pub use super::{DscpType, EcnType};

/// For now Ipv6ExtensionHeader fully supports only `HopByHopOptions`, `DestinationOptions` and `Fragment`, other variants presented just with `payload: Vec<u8>`
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
        /// Actually only 13 bits
        fragment_offset: u16,
        more_fragments: bool,
        /// Identification number for assembling with other fragments
        id: u32
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
impl Serializable for Ipv6ExtensionHeader {
    /// Converts IPv6 Extension Header to bytes with calculating correct padding automatically
    fn serialize(self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0u8; 2];
        match self {
            Self::HopByHopOptions {next_header, options} |
            Self::DestinationOptions {next_header, options} => {
                result[0] = next_header;
                for option in options {
                    result.append(&mut option.serialize());
                }
                let padding = 8 - result.len() % 8;
                if padding == 1 {
                    result.push(0);
                }
                else if padding > 1 {
                    result.push(1);
                    result.push(padding as u8 - 2);
                    result.append(&mut vec![0u8; padding - 2]);
                }
                result[1] = (result.len() / 8 - 1) as u8;
            }
            Self::Routing {next_header, mut payload} => {
                result[0] = next_header;
                result.append(&mut payload);
                result[1] = (result.len() / 8 - 1) as u8;
            }
            Self::Fragment {next_header, fragment_offset, more_fragments, id} => {
                result[0] = next_header;
                result[1] = 0;
                let fragment_offset = (fragment_offset << 3).to_be_bytes();
                result.push(fragment_offset[0]);
                result.push(fragment_offset[1] | more_fragments as u8);
                result.append(&mut id.to_be_bytes().to_vec());
            }
            Self::Mobility {next_header, mut payload} => {
                result[0] = next_header;
                result.append(&mut payload);
                result[1] = (result.len() / 8 - 1) as u8;
            }
        }
        result
    }
}
impl Ipv6ExtensionHeader {
    pub fn get_order(&self) -> usize {
        match self {
            Self::HopByHopOptions {..} => 0,
            Self::DestinationOptions {..} => 1,
            Self::Routing {..} => 2,
            Self::Fragment {..} => 3,
            Self::Mobility {..} => 4
        }
    }
    pub fn get_type(&self) -> u8 {
        match self {
            Self::HopByHopOptions {next_header: _, options: _} => 0,
            Self::Routing {next_header: _, payload: _} => 43,
            Self::Fragment {next_header: _, fragment_offset: _, more_fragments: _, id: _} => 44,
            Self::DestinationOptions {next_header: _, options: _} => 60,
            Self::Mobility {next_header: _, payload: _} => 135
        }
    }
    pub fn get_next_header_type(&self) -> u8 {
        match self {
            Self::HopByHopOptions {next_header, options: _} => *next_header,
            Self::Routing {next_header, payload: _} => *next_header,
            Self::Fragment {next_header, fragment_offset: _, more_fragments: _, id: _} => *next_header,
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
impl Serializable for Ipv6Option {
    fn serialize(mut self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.push(self.kind);
        result.push(self.data.len() as u8);
        result.append(&mut self.data);
        result
    }
}
impl Deserializable for Ipv6Option {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 2 {return Err(DeserializeError::WrongDataLength);}
        Ok(Self {
            kind: bytes[0],
            data: bytes[2..2 + bytes[1] as usize].to_vec()
        })
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
    /// Next header type
    pub next_header: u8,
    /// The same as TTL in Ipv4Packet
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub extension_headers: Vec<Ipv6ExtensionHeader>,
    pub payload: Vec<u8>
}
impl Ipv6Packet {
    pub fn new() -> Self {
        Self {
            dscp: DscpType::BE,
            ecn: EcnType::NotECT,
            flow_label: 0,
            next_header: 0,
            hop_limit: 0,
            source: Ipv6Addr::from_bits(0),
            destination: Ipv6Addr::from_bits(0),
            extension_headers: Vec::new(),
            payload: Vec::new()
        }
    }
}
impl Serializable for Ipv6Packet {
    fn serialize(mut self) -> Vec<u8> {
        let mut result = vec![0u8; 40];
        result[0] = 6 << 4;
        let dscp = self.dscp.serialize()[0];
        result[0] |= dscp >> 2;
        result[1] = dscp << 6;
        result[1] |= self.ecn.serialize()[0] << 4;
        let flow_label = self.flow_label.to_be_bytes();
        result[1] |= flow_label[1] & 0xF;
        result[2] = flow_label[2];
        result[3] = flow_label[3];
        result[6] = self.next_header;
        result[7] = self.hop_limit;
        result[8..24].copy_from_slice(&self.source.octets());
        result[24..40].copy_from_slice(&self.destination.octets());
        let mut payload_length = 0;
        for header in self.extension_headers {
            let mut header_bytes = header.serialize();
            payload_length += header_bytes.len();
            result.append(&mut header_bytes);
        }
        payload_length += self.payload.len();
        result.append(&mut self.payload);
        result[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        result
    }
}
impl Deserializable for Ipv6Packet {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 40 {return Err(DeserializeError::WrongDataLength);}
        if (bytes[0] >> 4) != 6 {return Err(DeserializeError::WrongData);}
        let mut packet = Self::new();
        packet.dscp = DscpType::deserialize(&[((bytes[0] & 0xF) << 2) | ((bytes[1] & 192) >> 6)])?;
        packet.ecn = EcnType::deserialize(&[(bytes[1] & 48) >> 4])?;
        packet.flow_label = u32::from_be_bytes([0u8, bytes[1] & 0xF, bytes[2], bytes[3]]);
        packet.next_header = bytes[6];
        packet.hop_limit = bytes[7];
        packet.source = Ipv6Addr::from_octets(bytes[8..24].as_array().unwrap().clone());
        packet.destination = Ipv6Addr::from_octets(bytes[24..40].as_array().unwrap().clone());
        let mut next_header = bytes[6];
        let mut i = 40usize;
        loop {
            match next_header {
                0 => {
                    let length = (bytes[i + 1] as usize + 1) * 8 - 2;
                    let data = &bytes[i + 2..i + 2 + length];
                    let mut  options: Vec<Ipv6Option> = Vec::new();
                    let mut j = 0usize;
                    while j < length {
                        if data[j] == 0 {
                            j += 1;
                        }
                        else if data[j] == 1 {
                            j += data[j + 1] as usize + 2;
                        }
                        else {
                            options.push(Ipv6Option::deserialize(&data[j..])?);
                            j += data[j + 1] as usize + 2;
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
                    let fragment_offset = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) >> 3;
                    packet.extension_headers.push(Ipv6ExtensionHeader::Fragment {
                        next_header: bytes[i],
                        fragment_offset,
                        more_fragments: (bytes[i + 3] & 1) != 0,
                        id: u32::from_be_bytes(bytes[i + 4..i + 8].as_array().unwrap().clone())
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
                            j += 1;
                        }
                        else if data[j] == 1 {
                            j += data[j + 1] as usize + 2;
                        }
                        else {
                            options.push(Ipv6Option::deserialize(&data[j..])?);
                            j += data[j + 1] as usize + 2;
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
        Ok(packet)
    }
}