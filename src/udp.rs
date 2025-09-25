use std::net::IpAddr;
use crate::util::{Packet, checksum};

/// Struct for ordinary TCP Packet
/// You can construct it from scratch with `UdpPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `UdpPacket::from_bytes()`
/// All `u16` fields of this packet **are not in big-endian order**
/// All `u16` fields of this packet **are in native order**
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// Source Port in native bytes order
    pub source: u16,
    /// Destination Port in native bytes order
    pub destination: u16,
    /// Total packet length in native bytes order
    pub length: u16,
    /// UDP Checksum in native bytes order
    pub checksum: u16,
    /// Packet Data
    pub payload: Vec<u8>
}
impl UdpPacket {
    /// Constructs an empty `UdpPacket`
    pub fn new() -> Self {
        Self {
            source: 0,
            destination: 0,
            length: 0,
            checksum: 0,
            payload: Vec::new()
        }
    }
    /// Recalculates all fields
    pub fn recalculate_all(&mut self, source_ip: IpAddr, destination_ip: IpAddr) -> () {
        self.recalculate_length();
        self.recalculate_checksum(source_ip, destination_ip);
    }
    /// Recalculates `length` field in `UdpPacket`
    pub fn recalculate_length(&mut self) -> () {
        self.length = self.to_bytes().len() as u16;
    }
    /// Recalculates `checksum` field in `TcpPacket`
    /// Note that to calculate TCP Checksum you also need source ip and destination ip from IP packet
    pub fn recalculate_checksum(&mut self, source_ip: IpAddr, destination_ip: IpAddr) -> () {
        let mut packet = self.to_bytes();
        packet[6] = 0;
        packet[7] = 0;
        match (source_ip, destination_ip) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let mut pseudo_header = Vec::<u8>::with_capacity(8 + packet.len());
                pseudo_header.append(&mut source.octets().to_vec());
                pseudo_header.append(&mut destination.octets().to_vec());
                pseudo_header.push(0);
                pseudo_header.push(17);
                pseudo_header.append(&mut (packet.len() as u16).to_be_bytes().to_vec());
                pseudo_header.append(&mut packet);
                self.checksum = checksum(pseudo_header);
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut pseudo_header = Vec::<u8>::with_capacity(48 + packet.len());
                pseudo_header.append(&mut source.octets().to_vec());
                pseudo_header.append(&mut destination.octets().to_vec());
                pseudo_header.append(&mut (packet.len() as u32).to_be_bytes().to_vec());
                pseudo_header.append(&mut vec![0; 3]);
                pseudo_header.push(17);
                pseudo_header.append(&mut packet);
                self.checksum = checksum(pseudo_header);
            }
            _ => panic!("'source_ip' and 'destination_ip' must have same type!")
        }
    }
}
impl Packet for UdpPacket {
    /// Constructs `UdpPacket` from existing packet bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            source: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes[8..].to_vec()
        }
    }
    /// Converting **only header** of packet to bytes
    fn header_to_bytes(&self) -> Vec<u8> {
        [
            self.source.to_be_bytes(),
            self.destination.to_be_bytes(),
            self.length.to_be_bytes(),
            self.checksum.to_be_bytes()
        ].concat()
    }
    /// Converting **full** packet to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.header_to_bytes();
        packet.append(&mut self.payload.clone());
        packet
    }
}