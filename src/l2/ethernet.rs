use crate::util::{Deserializable, DeserializeError, Serializable};

/// Struct for oridinary Ethernet Frame
/// You can construct it from scratch with `EthernetPacket::new()` and consistently editing
/// Or construct from existing frame bytes with `EthernetPacket::deserialize()`
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub protocol: u16,
    pub payload: Vec<u8>
}
impl EthernetFrame {
    /// Constructs an empty `EthernetPacket`
    pub fn new() -> Self {
        Self {
            destination: [0u8; 6],
            source: [0u8; 6],
            protocol: 0,
            payload: Vec::new()
        }
    }
}
impl Serializable for EthernetFrame {
    fn serialize(mut self) -> Vec<u8> {
        let mut result = Vec::new();
        result.append(&mut self.destination.to_vec());
        result.append(&mut self.source.to_vec());
        result.append(&mut self.protocol.to_be_bytes().to_vec());
        result.append(&mut self.payload);
        result
    }
}
impl Deserializable for EthernetFrame {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 15 {return Err(DeserializeError::WrongDataLength);}
        Ok(Self {
            destination: bytes[0..6].as_array().unwrap().clone(),
            source: bytes[6..12].as_array().unwrap().clone(),
            protocol: u16::from_be_bytes([bytes[12], bytes[13]]),
            payload: bytes[14..].to_vec()
        })
    }
}