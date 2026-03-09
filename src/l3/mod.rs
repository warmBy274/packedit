pub mod ipv4;
pub mod ipv6;
pub mod arp;
use crate::util::{Deserializable, DeserializeError, Serializable};

/// Differentiated Services Code Point, used for classify and mark packets within the framework of QoS(Quality of Service)
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DscpType {
    /// Best Effort | Class Selector 0 - just normal traffic
    BE = 0,
    /// Class Selector 1 - low priority
    CS1 = 8,
    /// Assured Forwarding 1.1 - low priority, low drop risk
    AF1_1 = 10,
    /// Assured Forwarding 1.2 - low priority, medium drop risk
    AF1_2 = 12,
    /// Assured Forwarding 1.3 - low priority, high drop risk
    AF1_3 = 14,
    /// Class Selector 2 - network control: SNMP, SSH, SCP, RDP, etc.
    CS2 = 16,
    /// Assured Forwarding 2.1 - medium priority, low drop risk
    AF2_1 = 18,
    /// Assured Forwarding 2.2 - medium priority, medium drop risk
    AF2_2 = 20,
    /// Assured Forwarding 2.3 - medium priority, high drop risk
    AF2_3 = 22,
    /// Class Selector 3 - audiostreaming
    CS3 = 24,
    /// Assured Forwarding 3.1 - high priority, low drop risk
    AF3_1 = 26,
    /// Assured Forwarding 3.2 - high priority, medium drop risk
    AF3_2 = 28,
    /// Assured Forwarding 3.3 - high priority, high drop risk
    AF3_3 = 30,
    /// Class Selector 4 - videostreaming
    CS4 = 32,
    /// Assured Forwarding 4.1 - critical priority, low drop risk
    AF4_1 = 34,
    /// Assured Forwarding 4.2 - critical priority, medium drop risk
    AF4_2 = 36,
    /// Assured Forwarding 4.3 - critical priority, high drop risk
    AF4_3 = 38,
    /// Class Selector 5 - connection control messages: SIP, H.323, etc.
    CS5 = 40,
    /// Class Selector 6 - network control high priority
    CS6 = 48,
    /// Class Selector 7 - network management: ICPM, OSPF, IGMP, etc.
    CS7 = 56,
    /// Expedited Forwarding - VoIP, low latency, highest priority
    EF = 46,
    /// Your custom DSCP type
    #[cfg(feature = "custom-types")]
    Custom(u8)
}
impl Serializable for DscpType {
    fn serialize(self) -> Vec<u8> {
        #[cfg(feature = "custom-types")]
        match self {
            Self::BE => vec![0],
            Self::CS1 => vec![8],
            Self::AF1_1 => vec![10],
            Self::AF1_2 => vec![12],
            Self::AF1_3 => vec![14],
            Self::CS2 => vec![16],
            Self::AF2_1 => vec![18],
            Self::AF2_2 => vec![20],
            Self::AF2_3 => vec![22],
            Self::CS3 => vec![24],
            Self::AF3_1 => vec![26],
            Self::AF3_2 => vec![28],
            Self::AF3_3 => vec![30],
            Self::CS4 => vec![32],
            Self::AF4_1 => vec![34],
            Self::AF4_2 => vec![36],
            Self::AF4_3 => vec![38],
            Self::CS5 => vec![40],
            Self::CS6 => vec![48],
            Self::CS7 => vec![56],
            Self::EF => vec![46],
            Self::Custom(custom) => vec![custom]
        }
        #[cfg(not(feature = "custom-types"))]
        return vec![self as u8];
    }
}
impl Deserializable for DscpType {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() == 0 {return Err(DeserializeError::WrongDataLength);}
        match bytes[0] {
            0 => Ok(Self::BE),
            8 => Ok(Self::CS1),
            10 => Ok(Self::AF1_1),
            12 => Ok(Self::AF1_2),
            14 => Ok(Self::AF1_3),
            16 => Ok(Self::CS2),
            18 => Ok(Self::AF2_1),
            20 => Ok(Self::AF2_2),
            22 => Ok(Self::AF2_3),
            24 => Ok(Self::CS3),
            26 => Ok(Self::AF3_1),
            28 => Ok(Self::AF3_2),
            30 => Ok(Self::AF3_3),
            32 => Ok(Self::CS4),
            34 => Ok(Self::AF4_1),
            36 => Ok(Self::AF4_2),
            38 => Ok(Self::AF4_3),
            40 => Ok(Self::CS5),
            48 => Ok(Self::CS6),
            56 => Ok(Self::CS7),
            46 => Ok(Self::EF),
            #[cfg(feature = "custom-types")]
            custom => Ok(Self::Custom(custom)),
            #[cfg(not(feature = "custom-types"))]
            _ => Err(DeserializeError::WrongData)
        }
    }
}

/// Explicit Congestion Notification
#[derive(Debug, Clone, Copy)]
pub enum EcnType {
    // Transport doesnt support ECN
    NotECT,
    // ECN Capable Transport(supports ECN) type 0
    ECT0,
    // ECN Capable Transport(supports ECN) type 1
    ECT1,
    // Congestion Expirienced
    CE
}
impl Serializable for EcnType {
    fn serialize(self) -> Vec<u8> {
        vec![self as u8]
    }
}
impl Deserializable for EcnType {
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        if bytes.len() == 0 {return Err(DeserializeError::WrongDataLength);}
        match bytes[0] {
            0 => Ok(Self::NotECT),
            1 => Ok(Self::ECT0),
            2 => Ok(Self::ECT1),
            3 => Ok(Self::CE),
            _ => Err(DeserializeError::WrongData)
        }
    }
}