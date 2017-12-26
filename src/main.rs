extern crate pcap;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate arrayref;

use pcap::{Device, Capture};
use nom::{Endianness, IResult, be_u8};
use std::net::Ipv4Addr;


fn main() {
    let device = Device::list()
        .unwrap()
        .into_iter()
        .filter(|device| {device.name == "enp3s0"})
        .next()
        .unwrap();
    let mut capture = Capture::from_device(device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(pkt) = capture.next() {
        if let IResult::Done(rest, frame) = ether_frame(pkt.data) {
            println!("{:?}", frame);
            if frame.ethernet_type == EtherType::IPv4 {
                if let IResult::Done(ip_rest, ip_header) = ip_parse(rest) {
                    println!("{:?}", ip_header);
                    match ip_header.protocol {
                        TransportProtocol::TCP => {
                            if let IResult::Done(tcp_rest, tcp_header) = tcp_parser(ip_rest) {
                                println!("{:?}", tcp_header);
                            }
                        },
                        TransportProtocol::UDP => {
                            if let IResult::Done(udp_payload, udp_header) = udp_parser(ip_rest) {
                                println!("{:?}", udp_header);
                            }
                        },
                        TransportProtocol::ICMP => {
                            if let IResult::Done(icmp_payload, icmp_header) = parse_icmp(ip_rest) {
                                println!("{:?}", icmp_header)
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
    }
}


fn list_devices(devices: Vec<Device>) {
    println!("===== Devices ======");
    for device in devices {
        println!("Device name: {}", device.name);
        println!("Descrition: {}", match device.desc {
            Some(description) => description,
            None => "None".to_string()
        });
        println!("==================");
    }
}


#[derive(Debug,PartialEq,Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    VLAN
}


pub fn to_ethertype(ether_type: u16) -> Option<EtherType> {
    match ether_type {
        0x0800 => Some(EtherType::IPv4),
        0x0806 => Some(EtherType::ARP),
        0x8100 => Some(EtherType::VLAN),
        0x86DD => Some(EtherType::IPv6),
        _ => None
    }
}

#[derive(PartialEq,Eq)]
pub struct MacAddress(pub [u8; 6]);

impl std::fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
    }
}

pub fn create_mac_address(octets: &[u8]) -> MacAddress {
    MacAddress(array_ref![octets, 0, 6].clone())
}

#[derive(Debug,PartialEq,Eq)]
pub struct EthernetFrame {
    pub source: MacAddress,
    pub destination: MacAddress,
    pub ethernet_type: EtherType
}

named!(mac_address<&[u8], MacAddress>, map!(take!(6), create_mac_address));
named!(ethertype<&[u8], EtherType>, map_opt!(u16!(Endianness::Big), to_ethertype));
named!(ether_frame<&[u8], EthernetFrame>, do_parse!(
        dest_mac: mac_address >>
        src_mac: mac_address >>
        ether_type: ethertype >>
        (EthernetFrame {source: src_mac, destination: dest_mac, ethernet_type: ether_type})
));


#[derive(Debug,PartialEq,Eq)]
pub struct Ipv4Packet {
    version: u8,
    ihl: u8,
    ecn: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: TransportProtocol,
    check_sum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}


#[derive(Debug,PartialEq,Eq)]
pub enum TransportProtocol {
    HOPOPT,
    ICMP,
    IGMP,
    GGP,
    IPIP,
    ST,
    TCP,
    CBT,
    EGP,
    NVPII,
    UDP,
    HMP,
    RDP,
    IRTP,
    ISOTP4,
    NETBLT,
    DCCP,
    IDRP,
    IL,
    IPv6,
    SDRP,
    IPv6Route,
    IPv6Frag,
    RSVP,
    GREs,
    DSR,
    UDPLite,
}



pub fn to_transport_protocol(proto: u8) -> Option<TransportProtocol> {
    match proto {
        0x01 => Some(TransportProtocol::ICMP),
        0x02 => Some(TransportProtocol::IGMP),
        0x06 => Some(TransportProtocol::TCP),
        0x08 => Some(TransportProtocol::EGP),
        0x11 => Some(TransportProtocol::UDP),
        0x88 => Some(TransportProtocol::UDPLite),
        _ => None
    }
}


pub fn make_address(addr: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(
        addr[0].clone(),
        addr[1].clone(),
        addr[2].clone(),
        addr[3].clone()
    )
}


named!(two_nibbles<&[u8], (u8, u8)>, bits!(pair!(take_bits!(u8, 4), take_bits!(u8, 4))));
named!(flag_frag_offset<&[u8], (u8, u16)>, bits!(pair!(take_bits!(u8, 3), take_bits!(u16, 13))));
named!(proto<&[u8], TransportProtocol>, map_opt!(be_u8, to_transport_protocol));
named!(address<&[u8], Ipv4Addr>, map!(take!(4), make_address));

named!(ip_parse<&[u8], Ipv4Packet>, do_parse!(
        ver_ihl: two_nibbles >>
        ecn: be_u8 >>
        length: u16!(Endianness::Big) >>
        id: u16!(Endianness::Big) >>
        flagsfragoff: flag_frag_offset >>
        ttl: be_u8 >>
        protocol: proto >>
        chksum: u16!(Endianness::Big) >>
        src_addr: address >>
        dst_addr: address >>
        options: take!((ver_ihl.1 - 5) * 4) >>
        (
            Ipv4Packet {
                version: ver_ihl.0,
                ihl: ver_ihl.1,
                ecn: ecn,
                total_length: length,
                id: id,
                flags: flagsfragoff.0,
                fragment_offset: flagsfragoff.1,
                ttl: ttl,
                protocol: protocol,
                check_sum: chksum,
                source: src_addr,
                destination: dst_addr,
            }    
        )
));


#[derive(Debug,PartialEq,Eq)]
pub struct TcpHeader {
    source: u16,
    destination: u16,
    sequence_number: u32,
    ack_number: u32,
    data_offset: u8,
    flags: Vec<TcpFlag>,
    window_size: u16,
    check_sum: u16,
    urgent_pointer: u16
}


#[derive(Debug,PartialEq,Eq,Clone)]
pub enum TcpFlag {
    NS  = 0x0100,
    CWR = 0x0080,
    ECE = 0x0040,
    URG = 0x0020,
    ACK = 0x0010,
    PSH = 0x0008,
    RST = 0x0004,
    SYN = 0x0002,
    FIN = 0x0001
}

const TCP_FLAGS: [TcpFlag; 9] = [TcpFlag::FIN, TcpFlag::SYN, TcpFlag::RST, TcpFlag::PSH,
                                 TcpFlag::ACK, TcpFlag::URG, TcpFlag::ECE, TcpFlag::CWR,
                                 TcpFlag::NS];

pub fn parse_tcp_flags(flags: u16) -> Vec<TcpFlag> {
    let mut flags_vec: Vec<TcpFlag> = vec![];
    
    for tcp_flag in &TCP_FLAGS {
        if is_flag_set(tcp_flag.clone(), flags) {
            flags_vec.push(tcp_flag.clone());
        }
    }

    flags_vec
}


pub fn is_flag_set(flag: TcpFlag, flags: u16) -> bool {
    let f_int = flag as u16;
    (f_int & flags) == f_int
}

pub fn is_set(flag: u16, flags: u16) -> bool {
    (flag & flags) == flag
}

named!(data_off_flags<&[u8], (u8, u16)>, bits!(pair!(take_bits!(u8, 4), take_bits!(u16, 12))));
named!(tcp_parser<&[u8], TcpHeader>, do_parse!(
        src: u16!(Endianness::Big) >>
        dst: u16!(Endianness::Big) >>
        seq_num: u32!(Endianness::Big) >>
        ack_num: u32!(Endianness::Big) >>
        doff_flags: data_off_flags >>
        wnd_size: u16!(Endianness::Big) >>
        chksum: u16!(Endianness::Big) >>
        urg_ptr: u16!(Endianness::Big) >>
        (
            TcpHeader {
                source: src,
                destination: dst,
                sequence_number: seq_num,
                ack_number: ack_num,
                data_offset: doff_flags.0,
                flags: parse_tcp_flags(doff_flags.1),
                window_size: wnd_size,
                check_sum: chksum,
                urgent_pointer: urg_ptr
            }
        )
));

#[derive(Debug,Eq,PartialEq)]
struct UdpHeader {
    source: u16,
    destination: u16,
    length: u16,
    check_sum: u16,
}

named!(udp_parser<&[u8], UdpHeader>, do_parse!(
        src: u16!(Endianness::Big) >>
        dst: u16!(Endianness::Big) >>
        len: u16!(Endianness::Big) >>
        chksum: u16!(Endianness::Big) >>
        (
            UdpHeader {
                source: src,
                destination: dst,
                length: len,
                check_sum: chksum
            }
        )
));

#[derive(Debug,Eq,PartialEq)]
struct IcmpHeader {
    icmp_type: IcmpType,
    code: u8,
    check_sum: u16
}

#[derive(Debug,Eq,PartialEq)]
pub enum IcmpType {
    EchoReply,
    DestinationUreachable,
    SourceQuench,
    RedirectMessage,
    EchoRequest,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    ParameterProblemBadIpHeader,
    Timestamp,
    TimestampReply,
    InformationRequest,
    InformationReply,
    AddressMaskRequest,
    AddressMaskReply,
    Traceroute
}

impl IcmpType {
    pub fn from_code(type_: u8) -> Option<IcmpType> {
        match type_ {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::DestinationUreachable),
            4 => Some(IcmpType::SourceQuench),
            5 => Some(IcmpType::RedirectMessage),
            8 => Some(IcmpType::EchoRequest),
            9 => Some(IcmpType::RouterAdvertisement),
            10 => Some(IcmpType::RouterSolicitation),
            11 => Some(IcmpType::TimeExceeded),
            12 => Some(IcmpType::ParameterProblemBadIpHeader),
            13 => Some(IcmpType::Timestamp),
            14 => Some(IcmpType::TimestampReply),
            15 => Some(IcmpType::InformationRequest),
            16 => Some(IcmpType::InformationReply),
            17 => Some(IcmpType::AddressMaskRequest),
            18 => Some(IcmpType::AddressMaskReply),
            30 => Some(IcmpType::Traceroute),
            _ => None
        }
    }
}


named!(parse_icmp<&[u8], IcmpHeader>, do_parse!(
        type_: be_u8 >>
        code: be_u8 >>
        chksum: u16!(Endianness::Big) >>
        (
            IcmpHeader {
                icmp_type: IcmpType::from_code(type_).unwrap(),
                code: code,
                check_sum: chksum
            }
        )
));
