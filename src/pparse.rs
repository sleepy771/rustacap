

enum Direction {
    SOURCE,
    DESTINATION,
}


pub fn get_mac_address<'a>(etherframe: &'a [u8], dir: Direction) -> &'a [u8] {
    match dir {
        Direction::DESTINATION => &etherframe[0..6],
        Direction::SOURCE => &etherframe[6..16]
    }
}


#[derive(Debug,PartialEq,Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    VLAN
}


pub fn get_ethertype(octets: &[u8]) -> Option<EtherType> {
    if octets[12] == 0x81 && octets[13] == 0x00 {
        to_ethertype(octets[16..])
    } else {
        to_ethertype(octets[12..])
    }
}


pub fn to_ethertype(ether_type: &[u8]) -> Option<EtherType> {
    match ether_type[..2] {
        &[0x08, 0x00] => Some(EtherType::IPv4),
        &[0x08, 0x06] => Some(EtherType::ARP),
        &[0x86, 0xDD] => Some(EtherType::IPv6),
        _ => None
    }
}

pub fn get_vlan_tag(octets: &[u8]) -> Option<u16> {
    if octets[12 .. 14] == &[0x81, 0x00] {
        Some(((octets[14] << 8) as u16) | octets[15])
    } else {
        None
    }
}
