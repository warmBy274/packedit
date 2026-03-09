use core::net::Ipv4Addr;

use crate::util::{Serializable, Deserializable, DeserializeError};

pub enum ArpOperation {
    Request = 1,
    Reply = 2
}
impl Serializable for ArpOperation {
    fn serialize(self) -> Vec<u8> {
        vec![self as u8]
    }
}
impl Deserializable for ArpOperation {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 2 {return Err(DeserializeError::WrongDataLength);}
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            1 => Ok(Self::Request),
            2 => Ok(Self::Reply),
            _ => Err(DeserializeError::WrongData)
        }
    }
}

pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr
}
impl ArpPacket {
    pub fn new() -> Self {
        Self {
            operation: ArpOperation::Request,
            sender_mac: [0; 6],
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [255; 6],
            target_ip: Ipv4Addr::UNSPECIFIED
        }
    }
}
impl Serializable for ArpPacket {
    fn serialize(self) -> Vec<u8> {
        let mut result = vec![0u8; 28];
        result[1] = 1;
        result[2] = 8;
        result[4] = 6;
        result[5] = 4;
        result[6..8].copy_from_slice(&self.operation.serialize());
        result[8..14].copy_from_slice(&self.sender_mac);
        result[14..18].copy_from_slice(&self.sender_ip.octets());
        result[18..24].copy_from_slice(&self.target_mac);
        result[24..28].copy_from_slice(&self.target_ip.octets());
        result
    }
}
impl Deserializable for ArpPacket {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() != 28 {return Err(DeserializeError::WrongDataLength);}
        if bytes[0] != 0 || bytes[1] != 1 {return Err(DeserializeError::WrongData);}
        if bytes[2] != 8 || bytes[3] != 0 {return Err(DeserializeError::WrongData);}
        if bytes[4] != 6 {return Err(DeserializeError::WrongData);}
        if bytes[5] != 4 {return Err(DeserializeError::WrongData);}
        Ok(Self {
            operation: ArpOperation::deserialize(&bytes[6..8])?,
            sender_mac: bytes[8..14].as_array().unwrap().clone(),
            sender_ip: Ipv4Addr::from_octets(bytes[14..18].as_array().unwrap().clone()),
            target_mac: bytes[18..24].as_array().unwrap().clone(),
            target_ip: Ipv4Addr::from_octets(bytes[24..28].as_array().unwrap().clone())
        })
    }
}