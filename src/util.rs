use paste::paste;

macro_rules! hardware_address {
    ($name:ident, $desc:expr, $size:expr) => {
        paste! {
            #[doc = $desc]
            #[derive(Debug, Clone, Copy)]
            pub struct [<$name Address>] {
                /// $name Address Data Bytes
                pub bytes: [u8; $size]
            }
            impl [<$name Address>] {
                pub fn new() -> Self {
                    Self {
                        bytes: [0u8; $size]
                    }
                }
                pub fn from_slice(bytes: &[u8]) -> Self {
                    if bytes.len() < $size {
                        panic!("Bytes len must be $size!");
                    }
                    let mut new_bytes: [u8; $size] = [0; $size];
                    new_bytes.copy_from_slice(bytes);
                    Self {
                        bytes: new_bytes
                    }
                }
                pub fn from_bytes(bytes: [u8; $size]) -> Self {
                    Self {
                        bytes: bytes
                    }
                }
                pub fn to_bytes(&self) -> [u8; $size] {
                    self.bytes
                }
            }
        }
    };
}

#[cfg(feature = "legacy-arp")]
#[derive(Debug, Clone)]
pub enum HardwareAddress {
    Mac(MacAddress),
    Ax25(Ax25Address),
    Atm(AtmAddress),
    Gid(GidAddress),
    Wwn(WwnAddress),
    Node(NodeAddress),
    None
}
#[cfg(feature = "legacy-arp")]
impl HardwareAddress {
    pub fn new() -> Self {
        Self::None
    }
}

hardware_address!(Mac, "Media Access Control address\nUsed in Ethernet, Experimental Ethernet, Token Ring, FDDI and other", 6);
#[cfg(feature = "legacy-arp")]
hardware_address!(Ax25, "Amateur Radio\nCallsign 6 bytes + SSID 1 byte", 7);
#[cfg(feature = "legacy-arp")]
hardware_address!(Atm, "NSAP or ATM address", 20);
#[cfg(feature = "legacy-arp")]
hardware_address!(Gid, "GID(IB) address\nGUID 16 bytes + prefix 4 bytes", 20);
#[cfg(feature = "legacy-arp")]
hardware_address!(Wwn, "World Wide Name\nUsed in Fibre Channel, ATA, SAS", 8);
#[cfg(feature = "legacy-arp")]
hardware_address!(Node, "Just Node ID, used in small networks, like ARCNET or something else", 1);

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