use std::net::Ipv4Addr;
use crate::util::checksum;

/// TCP Packet Option struct for `TcpPacket`
/// TCP Option are consist of:
///   1. 1 byte Kind
///   2. 1 byte Length in bytes
///   3. N bytes data
#[derive(Debug, Clone)]
pub struct TcpOption {
    /// TCP Option *'type'*
    pub kind: u8,
    /// TCP Option total length in bytes
    pub length: u8,
    /// TCP Option data
    pub data: Vec<u8>
}
impl TcpOption {
    /// Constructs an empty `TcpOption`
    pub fn new() -> Self {
        Self {
            kind: 0,
            length: 0,
            data: Vec::new()
        }
    }
    /// Constructs `TcpOption` from bytes
    /// Note that this method is not detecting where option starts and where ends
    /// This method **is not parsing options**, this method **exclusively constructs an one option**
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            kind: bytes[0],
            length: bytes[1],
            data: bytes[2..].to_vec()
        }
    }
    /// Converts option to bytes without padding
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut option = vec![0u8; 2];
        option[0] = self.kind;
        option[1] = self.length;
        option.append(&mut self.data.clone());
        option
    }
    /// Recalculates `length` field of option base on data len
    pub fn recalculate_length(&mut self) -> () {
        self.length = self.data.len() as u8 + 2;
    }
}

/// Struct for TCP Packet Flags in normal order for `TcpPacket`
/// Note that normal TCP Packet Flags order are: `nonce_sum`, `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn` and `fin`
#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub nonce_sum: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool
}
impl TcpFlags {
    /// Constructs a new `TcpFlags`
    pub fn new() -> Self {
        Self {
            nonce_sum: false,
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false
        }
    }
    /// Constructs new `TcpFlags` from existing `nonce_sum` flag as `bool` and other 8 flags in normal tcp order in `u8` variable
    /// Note that 'normal tcp order' for TCP Packet Flags are: `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn` and `fin`
    pub fn from_bits(nonce_sum: bool, other: u8) -> Self {
        Self {
            nonce_sum: nonce_sum,
            cwr: (other & 128) != 0,
            ece: (other & 64) != 0,
            urg: (other & 32) != 0,
            ack: (other & 16) != 0,
            psh: (other & 8) != 0,
            rst: (other & 4) != 0,
            syn: (other & 2) != 0,
            fin: (other & 1) != 0
        }
    }
    /// Returns `nonce_sum` flag in `bool` and other flags in normal tcp order as `u8`
    /// Note that 'normal tcp order' for TCP Packet Flags are: `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn` and `fin`
    pub fn to_bits(&self) -> (bool, u8) {
        let mut byte = (self.cwr as u8) << 7;
        byte |= (self.ece as u8) << 6;
        byte |= (self.urg as u8) << 5;
        byte |= (self.ack as u8) << 4;
        byte |= (self.psh as u8) << 3;
        byte |= (self.rst as u8) << 2;
        byte |= (self.syn as u8) << 1;
        byte |= self.fin as u8;
        (self.nonce_sum, byte)
    }
}

/// Struct for ordinary TCP Packet
/// You can construct it from scratch with `TcpPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `TcpPacket::from_bytes()`
/// All `u16` fields of this packet **are not in big-endian order**
/// All `u16` fields of this packet **are in native order**
#[derive(Debug, Clone)]
pub struct TcpPacket {
    /// Source Port in native bytes order
    pub source: u16,
    /// Destination Port in native bytes order
    pub destination: u16,
    /// Sequence number in native bytes order
    pub sequence_number: u32,
    /// Acknowledgement number in native bytes order
    pub acknowledgement_number: u32,
    /// Data offset in bytes
    /// Note that this field **is measured in bytes** and **not in 32 bit or 2 byte words** unlike real TCP Packet field
    pub data_offset: u8,
    /// TCP Packet flags
    pub flags: TcpFlags,
    /// Window Size in native bytes order
    pub window_size: u16,
    /// TCP Checksum in native bytes order
    pub checksum: u16,
    /// Urgent Pointer in native bytes order
    pub urgent_pointer: u16,
    /// TCP Options
    pub options: Vec<TcpOption>,
    /// Packet Data
    pub payload: Vec<u8>
}
impl TcpPacket {
    /// Constructs an empty `TcpPacket`
    pub fn new() -> Self {
        Self {
            source: 0,
            destination: 0,
            sequence_number: 0,
            acknowledgement_number: 0,
            data_offset: 0,
            flags: TcpFlags::new(),
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
            payload: Vec::new()
        }
    }
    /// Constructs `TcpPacket` from existing packet bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.len() < 20 {
            panic!("Length of bytes is less than 20!");
        }
        let mut packet = Self::new();
        packet.source = u16::from_be_bytes([bytes[0], bytes[1]]);
        packet.destination = u16::from_be_bytes([bytes[2], bytes[3]]);
        packet.sequence_number = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        packet.acknowledgement_number = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        packet.data_offset = (bytes[12] >> 4) * 4;
        packet.flags = TcpFlags::from_bits((bytes[12] & 1) != 0, bytes[13]);
        packet.window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        packet.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        packet.urgent_pointer = u16::from_be_bytes([bytes[18], bytes[19]]);
        if bytes.len() > 20 {
            let mut i = 20usize;
            while i < packet.data_offset as usize {
                if bytes[i] == 0 {break;}
                if bytes[i] == 1 {
                    i += 1;
                    continue;
                }
                packet.options.push(TcpOption::from_bytes(bytes[i..i + bytes[i + 1] as usize].to_vec()));
                i += bytes[i + 1] as usize;
            }
        }
        packet.payload = bytes[packet.data_offset as usize..].to_vec();
        packet
    }
    /// Converting **only header** of packet to bytes
    pub fn header_to_bytes(&self) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0..=1].copy_from_slice(&self.source.to_be_bytes());
        packet[2..=3].copy_from_slice(&self.destination.to_be_bytes());
        packet[4..=7].copy_from_slice(&self.sequence_number.to_be_bytes());
        packet[8..=11].copy_from_slice(&self.acknowledgement_number.to_be_bytes());
        packet[12] = (self.data_offset / 4) << 4;
        let flags = self.flags.to_bits();
        packet[12] |= flags.0 as u8;
        packet[13] = flags.1;
        packet[14..=15].copy_from_slice(&self.window_size.to_be_bytes());
        packet[16..=17].copy_from_slice(&self.checksum.to_be_bytes());
        packet[18..=19].copy_from_slice(&self.urgent_pointer.to_be_bytes());
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
    /// Recalculates all fields
    pub fn recalculate_all(&mut self, source_ip: Ipv4Addr, destination_ip: Ipv4Addr) -> () {
        for option in self.options.iter_mut() {
            option.recalculate_length();
        }
        self.recalculate_data_offset();
        self.recalculate_checksum(source_ip, destination_ip);
    }
    /// Recalculates `data_offset` field in `TcpPacket`
    pub fn recalculate_data_offset(&mut self) -> () {
        let header = self.header_to_bytes().len();
        self.data_offset = header as u8;
    }
    /// Recalculates `checksum` field in `TcpPacket`
    /// Note that to calculate TCP Checksum you also need source ip and destination ip from IP packet
    pub fn recalculate_checksum(&mut self, source_ip: Ipv4Addr, destination_ip: Ipv4Addr) -> () {
        let mut packet = self.to_bytes();
        let mut pseudo_header = Vec::<u8>::with_capacity(32);
        pseudo_header.append(&mut source_ip.octets().to_vec());
        pseudo_header.append(&mut destination_ip.octets().to_vec());
        pseudo_header.push(0);
        pseudo_header.push(6);
        pseudo_header.append(&mut (packet.len() as u16).to_be_bytes().to_vec());
        pseudo_header.append(&mut packet);
        pseudo_header[28] = 0;
        pseudo_header[29] = 0;
        self.checksum = checksum(pseudo_header);
    }
}