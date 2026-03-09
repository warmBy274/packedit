use core::net::IpAddr;
use crate::util::{Serializable, Deserializable, DeserializeError, checksum};

/// TCP Packet Option struct for `TcpPacket`
/// TCP Option are consist of:
///   1. 1 byte Kind
///   2. 1 byte Length in bytes
///   3. N bytes data
#[derive(Debug, Clone)]
pub struct TcpOption {
    pub kind: u8,
    pub data: Vec<u8>
}
impl TcpOption {
    /// Constructs an empty `TcpOption`
    pub fn new() -> Self {
        Self {
            kind: 0,
            data: Vec::new()
        }
    }
}
impl Serializable for TcpOption {
    fn serialize(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len() + 2);
        result.push(self.kind);
        result.push(self.data.len() as u8 + 2);
        result.append(&mut self.data.clone());
        result
    }
}
impl Deserializable for TcpOption {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 2 {return Err(DeserializeError::WrongDataLength);}
        Ok(Self {
            kind: bytes[0],
            data: bytes[2..2 + bytes[1] as usize].to_vec()
        })
    }
}

/// Struct for TCP Packet Flags in normal order for `TcpPacket`
/// Note that normal TCP Packet Flags order are: `nonce_sum`, `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn` and `fin`
#[derive(Debug, Clone)]
pub struct TcpFlags {
    /// Nonce Sum - an experimental flag used to protect against accidental or malicious concealment of marked packets
    pub ns: bool,
    /// Congestion Window Reduced - set by the sender to indicate it received a packet with the ECE flag
    pub cwr: bool,
    /// ECN-Echo - indicates that the TCP peer is ECN capable or notifies of network congestion
    pub ece: bool,
    /// Urgent - indicates that the urgent pointer field is valid, signaling high-priority data
    pub urg: bool,
    /// Acknowledgement - confirms the successful receipt of a segment
    pub ack: bool,
    /// Push - forces buffered data to be delivered immediately to the application
    pub psh: bool,
    /// Reset - aborts a connection due error
    pub rst: bool,
    /// Synchronize - initiates new connection
    pub syn: bool,
    /// Finish - gracefully terminates a connection
    pub fin: bool
}
impl TcpFlags {
    /// Constructs a new `TcpFlags`
    pub fn new() -> Self {
        Self {
            ns: false,
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
}
impl Serializable for TcpFlags {
    fn serialize(self) -> Vec<u8> {
        vec![
            self.ns as u8,
            (self.cwr as u8) << 7 |
            (self.ece as u8) << 6 |
            (self.urg as u8) << 5 |
            (self.ack as u8) << 4 |
            (self.psh as u8) << 3 |
            (self.rst as u8) << 2 |
            (self.syn as u8) << 1 |
            self.fin as u8
        ]
    }
}
impl Deserializable for TcpFlags {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 2 {return Err(DeserializeError::WrongDataLength);}
        Ok(Self {
            ns: bytes[0] & 1 != 0,
            cwr: bytes[1] & 128 != 0,
            ece: bytes[1] & 64 != 0,
            urg: bytes[1] & 32 != 0,
            ack: bytes[1] & 16 != 0,
            psh: bytes[1] & 8 != 0,
            rst: bytes[1] & 4 != 0,
            syn: bytes[1] & 2 != 0,
            fin: bytes[1] & 1 != 0
        })
    }
}

/// Struct for ordinary TCP Packet
/// You can construct it from scratch with `TcpPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `TcpPacket::from_bytes()`
/// All `u16` and `u32` fields of this packet **are in native order**
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// Source Port
    pub source: u16,
    /// Destination Port
    pub destination: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>
}
impl TcpSegment {
    /// Constructs an empty `TcpPacket`
    pub fn new() -> Self {
        Self {
            source: 0,
            destination: 0,
            sequence_number: 0,
            acknowledgement_number: 0,
            flags: TcpFlags::new(),
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
            payload: Vec::new()
        }
    }
    /// Recalculates `checksum` field in `TcpPacket`
    /// Note that to calculate TCP Checksum you also need source ip and destination ip from IP packet
    /// Returns `Err(())` only when `source_ip` and `destination_ip` not same version, e.g. IPv4 and IPv6
    pub fn recalculate_checksum(&mut self, source_ip: IpAddr, destination_ip: IpAddr) -> Result<(), ()> {
        let mut packet = self.clone_header().serialize();
        packet[16] = 0;
        packet[17] = 0;
        match (source_ip, destination_ip) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let mut pseudo_header = Vec::<u8>::with_capacity(32 + packet.len());
                pseudo_header.append(&mut source.octets().to_vec());
                pseudo_header.append(&mut destination.octets().to_vec());
                pseudo_header.push(0);
                pseudo_header.push(6);
                pseudo_header.append(&mut (packet.len() as u16).to_be_bytes().to_vec());
                pseudo_header.append(&mut packet);
                self.checksum = checksum(pseudo_header);
                Ok(())
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut pseudo_header = Vec::<u8>::with_capacity(60 + packet.len());
                pseudo_header.append(&mut source.octets().to_vec());
                pseudo_header.append(&mut destination.octets().to_vec());
                pseudo_header.append(&mut (packet.len() as u32).to_be_bytes().to_vec());
                pseudo_header.append(&mut vec![0; 3]);
                pseudo_header.push(6);
                pseudo_header.append(&mut packet);
                self.checksum = checksum(pseudo_header);
                Ok(())
            }
            _ => Err(())
        }
    }
    pub fn clone_header(&self) -> Self {
        Self {
            payload: Vec::new(),
            ..self.clone()
        }
    }
}
impl Serializable for TcpSegment {
    fn serialize(mut self) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0..2].copy_from_slice(&self.source.to_be_bytes());
        packet[2..4].copy_from_slice(&self.destination.to_be_bytes());
        packet[4..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        packet[8..12].copy_from_slice(&self.acknowledgement_number.to_be_bytes());
        let flags = self.flags.serialize();
        packet[12] = flags[0];
        packet[13] = flags[1];
        packet[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        packet[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        packet[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        for option in self.options {
            let mut option_bytes = option.serialize();
            let option_padding = 4 - option_bytes.len() % 4;
            if option_padding != 0 {
                option_bytes.append(&mut vec![1; option_padding]);
            }
            packet.append(&mut option_bytes);
        }
        let padding = 4 - packet.len() % 4;
        if padding != 0 {
            packet.append(&mut vec![0; padding]);
        }
        packet[12] |= (packet.len() as u8 / 4) << 4;
        packet.append(&mut self.payload);
        packet
    }
}
impl Deserializable for TcpSegment {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 20 {return Err(DeserializeError::WrongDataLength);}
        let mut packet = Self::new();
        packet.source = u16::from_be_bytes([bytes[0], bytes[1]]);
        packet.destination = u16::from_be_bytes([bytes[2], bytes[3]]);
        packet.sequence_number = u32::from_be_bytes(bytes[4..8].as_array().unwrap().clone());
        packet.acknowledgement_number = u32::from_be_bytes(bytes[8..12].as_array().unwrap().clone());
        let data_offset = (bytes[12] as usize >> 4) * 4;
        packet.flags = TcpFlags::deserialize(&bytes[12..14])?;
        packet.window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        packet.checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        packet.urgent_pointer = u16::from_be_bytes([bytes[18], bytes[19]]);
        if data_offset > 20 {
            let mut i = 20usize;
            while i < data_offset as usize {
                if bytes[i] == 0 {break;}
                if bytes[i] == 1 {
                    i += 1;
                    continue;
                }
                packet.options.push(TcpOption::deserialize(&bytes[i..])?);
                i += bytes[i + 1] as usize;
            }
        }
        packet.payload = bytes[data_offset as usize..].to_vec();
        Ok(packet)
    }
}