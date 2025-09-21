use crate::util::{MacAddress, Packet};

/// Struct for oridinary Ethernet Frame
/// You can construct it from scratch with `EthernetPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `EthernetPacket::from_bytes()`
#[derive(Debug, Clone)]
pub struct EthernetPacket {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub protocol: u16,
    pub payload: Vec<u8>
}
impl EthernetPacket {
    /// Constructs an empty `EthernetPacket`
    pub fn new() -> Self {
        Self {
            destination: MacAddress::new(),
            source: MacAddress::new(),
            protocol: 0,
            payload: Vec::new()
        }
    }
}
impl Packet for EthernetPacket {
    /// Constructs `EthernetPacket` from existing ethernet frame bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 15 {
            panic!("Bytes len must be at least 15!");
        }
        Self {
            destination: MacAddress::from_slice(&bytes[0..=5]),
            source: MacAddress::from_slice(&bytes[6..=11]),
            protocol: u16::from_be_bytes([bytes[12], bytes[13]]),
            payload: bytes[14..].to_vec()
        }
    }
    fn header_to_bytes(&self) -> Vec<u8> {
        let mut packet = vec![0u8; 14];
        packet[0..=5].copy_from_slice(&self.destination.to_bytes());
        packet[6..=11].copy_from_slice(&self.source.to_bytes());
        packet[12..=13].copy_from_slice(&self.protocol.to_be_bytes());
        packet
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.header_to_bytes();
        packet.append(&mut self.payload.clone());
        packet
    }
}