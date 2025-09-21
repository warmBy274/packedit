/// Media Access Control address\nUsed in Ethernet, Experimental Ethernet, Token Ring, FDDI and other
#[derive(Debug, Clone, Copy)]
pub struct MacAddress {
    /// $name Address Data Bytes
    pub bytes: [u8; 6]
}
impl MacAddress {
    pub fn new() -> Self {
        Self {
            bytes: [0u8; 6]
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        if bytes.len() < 6 {
            panic!("Bytes len must be $size!");
        }
        let mut new_bytes: [u8; 6] = [0; 6];
        new_bytes.copy_from_slice(bytes);
        Self {
            bytes: new_bytes
        }
    }
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self {
            bytes: bytes
        }
    }
    pub fn to_bytes(&self) -> [u8; 6] {
        self.bytes
    }
}

pub trait Packet {
    fn from_bytes(bytes: &[u8]) -> Self;
    fn header_to_bytes(&self) -> Vec<u8>;
    fn to_bytes(&self) -> Vec<u8>;
}

/// **Sums up** all `16 bits` or `2 bytes` words(with adding `zero-byte` in end if `bytes.len() % 2 == 1`), **one's completing**, **inverting** and **returning** this sum
pub fn checksum(mut bytes: Vec<u8>) -> u16 {
    let mut sum = 0u32;
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    for word in bytes.chunks(2) {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32
    }
    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}