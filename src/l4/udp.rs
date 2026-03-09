use core::net::IpAddr;
use crate::util::{Serializable, Deserializable, DeserializeError, checksum};

/// Struct for ordinary TCP Packet
/// You can construct it from scratch with `UdpPacket::new()` and consistently editing
/// Or construct from existing packet bytes with `UdpPacket::from_bytes()`
/// All `u16` fields of this packet **are in native order**
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    /// Source Port
    pub source: u16,
    /// Destination Port
    pub destination: u16,
    pub checksum: Option<u16>,
    pub payload: Vec<u8>
}
impl UdpDatagram {
    /// Constructs an empty `UdpPacket`
    pub fn new() -> Self {
        Self {
            source: 0,
            destination: 0,
            checksum: None,
            payload: Vec::new()
        }
    }
    /// Recalculates `checksum` field in `TcpPacket`
    /// Note that to calculate TCP Checksum you also need source ip and destination ip from IP packet
    /// Returns `Err(())` only when `source_ip` and `destination_ip` not same version, e.g. IPv4 and IPv6
    pub fn recalculate_checksum(&mut self, source_ip: IpAddr, destination_ip: IpAddr) -> Result<(), ()> {
        let mut packet = self.clone_header().serialize();
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
                self.checksum = Some(checksum(pseudo_header));
                Ok(())
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut pseudo_header = Vec::<u8>::with_capacity(48 + packet.len());
                pseudo_header.append(&mut source.octets().to_vec());
                pseudo_header.append(&mut destination.octets().to_vec());
                pseudo_header.append(&mut (packet.len() as u32).to_be_bytes().to_vec());
                pseudo_header.append(&mut vec![0; 3]);
                pseudo_header.push(17);
                pseudo_header.append(&mut packet);
                self.checksum = Some(checksum(pseudo_header));
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
impl Serializable for UdpDatagram {
    fn serialize(mut self) -> Vec<u8> {
        let mut result = [
            self.source.to_be_bytes(),
            self.destination.to_be_bytes(),
            (8 + self.payload.len() as u16).to_be_bytes(),
            self.checksum.unwrap_or(0).to_be_bytes()
        ].concat();
        result.append(&mut self.payload);
        result
    }
}
impl Deserializable for UdpDatagram {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() < 8 {return Err(DeserializeError::WrongDataLength);}
        let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);
        Ok(Self {
            source: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination: u16::from_be_bytes([bytes[2], bytes[3]]),
            checksum: if checksum == 0 {None} else {Some(checksum)},
            payload: bytes[8..].to_vec()
        })
    }
}