#[derive(Debug, Clone, Copy)]
pub enum DscpType {
    /// Normal traffic
    CS0,
    /// Low priority
    CS1,
    /// Network control: SNMP, SSH, SCP, RDP, etc.
    CS2,
    /// Audiostreaming
    CS3,
    /// Videostreaming
    CS4,
    /// Connection control messages: SIP, H.323, etc.
    CS5,
    /// Network control high priority
    CS6,
    /// Network management: ICPM, OSPF, IGMP, etc.
    CS7,
    /// VoIP, low latency
    EF
}
impl DscpType {
    pub fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::CS0,
            8 => Self::CS1,
            16 => Self::CS2,
            24 => Self::CS3,
            32 => Self::CS4,
            40 => Self::CS5,
            48 => Self::CS6,
            56 => Self::CS7,
            46 => Self::EF,
            _ => panic!("DSCP value can be only 0, 8, 16, 24, 32, 40, 46, 48, 56!")
        }
    }
    pub fn to_bits(&self) -> u8 {
        match self {
            Self::CS0 => 0,
            Self::CS1 => 8,
            Self::CS2 => 16,
            Self::CS3 => 24,
            Self::CS4 => 32,
            Self::CS5 => 40,
            Self::CS6 => 48,
            Self::CS7 => 56,
            Self::EF => 46
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EcnType {
    NotECT,
    ECT0,
    ECT1,
    CE
}
impl EcnType {
    pub fn from_bits(value: u8) -> Self {
        match value {
            0b00 => Self::NotECT,
            0b01 => Self::ECT1,
            0b10 => Self::ECT0,
            0b11 => Self::CE,
            _ => panic!("ECN value must be less than 4!")
        }
    }
    pub fn to_bits(&self) -> u8 {
        match self {
            Self::NotECT => 0b00,
            Self::ECT1 => 0b01,
            Self::ECT0 => 0b10,
            Self::CE => 0b11
        }
    }
}

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