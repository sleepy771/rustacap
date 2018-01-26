extern crate pcap;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate arrayref;

use pcap::{Device, Capture};
use nom::{Endianness, IResult, be_u8};
use std::net::Ipv4Addr;

mod couters;

fn main() {
    let device = Device::list()
        .unwrap()
        .into_iter()
        .filter(|device| {device.name == "enp6s0"})
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
            if frame.ethernet_type == ether_type::IPV4 {
                if let IResult::Done(ip_rest, ip_header) = ip_parse(rest) {
                    println!("{:?}", ip_header);
                    match ip_header.protocol {
                        transport_proto::TCP => {
                            if let IResult::Done(tcp_rest, tcp_header) = tcp_parser(ip_rest) {
                                println!("{:?}", tcp_header);
                            }
                        },
                        transport_proto::UDP => {
                            if let IResult::Done(udp_payload, udp_header) = udp_parser(ip_rest) {
                                println!("{:?}", udp_header);
                            }
                        },
                        transport_proto::ICMP => {
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


pub mod ether_type {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP: u16 = 0x0806;
    pub const VLAN: u16 = 0x8100;
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
    pub ethernet_type: u16
}

named!(mac_address<&[u8], MacAddress>, map!(take!(6), create_mac_address));
named!(ethertype<&[u8], u16>, u16!(Endianness::Big));
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
    protocol: u8,
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

pub mod transport_proto {
    pub const ICMP: u8 = 0x01;
    pub const IGMP: u8 = 0x02;
    pub const TCP: u8 = 0x06;
    pub const EGP: u8 = 0x08;
    pub const UDP: u8 = 0x11;
    pub const UDP_LITE: u8 = 0x88;
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
named!(address<&[u8], Ipv4Addr>, map!(take!(4), make_address));

named!(ip_parse<&[u8], Ipv4Packet>, do_parse!(
        ver_ihl: two_nibbles >>
        ecn: be_u8 >>
        length: u16!(Endianness::Big) >>
        id: u16!(Endianness::Big) >>
        flagsfragoff: flag_frag_offset >>
        ttl: be_u8 >>
        protocol: be_u8 >>
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
    flags: u16,
    window_size: u16,
    check_sum: u16,
    urgent_pointer: u16
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
                flags: doff_flags.1,
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
    icmp_type: u8,
    code: u8,
    check_sum: u16
}

named!(parse_icmp<&[u8], IcmpHeader>, do_parse!(
        type_: be_u8 >>
        code: be_u8 >>
        chksum: u16!(Endianness::Big) >>
        (
            IcmpHeader {
                icmp_type: type_,
                code: code,
                check_sum: chksum
            }
        )
));
