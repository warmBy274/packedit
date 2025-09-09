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