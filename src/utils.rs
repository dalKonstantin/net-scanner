use std::net::Ipv4Addr;

use pnet::datalink::{DataLinkSender, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::MutablePacket;
use pnet::packet::arp::{ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::util::MacAddr;
use pnet::{
    datalink::{self},
    packet::ethernet::EtherTypes,
};

pub fn send_arp_discovery(
    tx: &mut dyn DataLinkSender,
    dest_ip: Ipv4Addr,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
) {
    tx.build_and_send(1, 42, &mut |packet_buffer| {
        let mut eth_packet =
            MutableEthernetPacket::new(packet_buffer).expect("Can't create buffer");
        // ---Ethernet---
        eth_packet.set_source(src_mac);
        eth_packet.set_destination(pnet::util::MacAddr::broadcast());
        eth_packet.set_ethertype(EtherTypes::Arp);
        //---ARP---
        let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
        arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6); // 6 bytes for MAC address
        arp_packet.set_proto_addr_len(4); // 4 bytes for IPv4
        arp_packet.set_operation(ArpOperations::Request); // ARP request
        arp_packet.set_sender_hw_addr(src_mac);
        arp_packet.set_sender_proto_addr(src_ip);
        arp_packet.set_target_hw_addr(pnet::util::MacAddr::zero());
        arp_packet.set_target_proto_addr(dest_ip);
    });
}

pub fn get_interface_by_name(name: &str) -> Option<NetworkInterface> {
    let ifaces = datalink::interfaces();

    let iface = ifaces
        .into_iter()
        .filter(|iface| iface.name == name)
        .next()?;
    Some(iface)
}

pub fn get_network_by_interface(iface: &NetworkInterface) -> Option<Ipv4Network> {
    let ipv4_network = iface.clone().ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(network) => Some(*network),
        _ => None,
    })?;
    Some(ipv4_network)
}

pub fn get_usable_ips_by_network(ipv4_network: &Ipv4Network) -> Option<Vec<Ipv4Addr>> {
    let all_ips: Vec<Ipv4Addr> = ipv4_network.iter().collect();
    let usable_ips: Vec<Ipv4Addr> = all_ips
        .iter()
        .copied()
        .skip(1)
        .take(all_ips.len() - 2 as usize)
        .collect();
    Some(usable_ips)
}

pub fn get_local_mac_by_interface(iface: &NetworkInterface) -> Option<MacAddr> {
    iface.mac
}
