/// Media Access Control Address
/// Contains 6 bytes
pub struct MacAddress {
    /// Mac Address Data Bytes
    pub bytes: [u8; 6]
}
impl MacAddress {
    /// Constructs an zero `MacAddress`
    pub fn new() -> Self {
        Self {
            bytes: [0, 0, 0, 0, 0, 0]
        }
    }
    /// Constructs `MacAddress` from byte slice
    pub fn from_slice(bytes: &[u8]) -> Self {
        if bytes.len() < 6 {
            panic!("Bytes len must be 6!");
        }
        Self {
            bytes: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
        }
    }
    /// Constructs `MacAddress` from byte array
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self {
            bytes: bytes
        }
    }
}

/// Struct for oridinary Ethernet Frame
/// You can construct it from scratch with `EthernetPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `EthernetPacket::from_bytes()`
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
    /// Constructs `EthernetPacket` from existing ethernet frame bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
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
}
