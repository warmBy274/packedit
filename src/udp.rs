use std::net::Ipv4Addr;
use crate::util::checksum;

/// Struct for ordinary TCP Packet
/// You can construct it from scratch with `UdpPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `UdpPacket::from_bytes()`
/// All `u16` fields of this packet **are not in big-endian order**
/// All `u16` fields of this packet **are in native order**
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
    /// Constructs `UdpPacket` from existing packet bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            source: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes[8..].to_vec()
        }
    }
    /// Converting **only header** of packet to bytes
    pub fn header_to_bytes(&self) -> Vec<u8> {
        [
            self.source.to_be_bytes(),
            self.destination.to_be_bytes(),
            self.length.to_be_bytes(),
            self.checksum.to_be_bytes()
        ].concat()
    }
    /// Converting **full** packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.header_to_bytes();
        packet.append(&mut self.payload.clone());
        packet
    }
    /// Recalculates `length` field in `UdpPacket`
    pub fn recalculate_length(&mut self) -> () {
        self.length = self.to_bytes().len() as u16;
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
        pseudo_header[18] = 0;
        pseudo_header[19] = 0;
        self.checksum = checksum(pseudo_header);
    }
}