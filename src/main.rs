use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use indicatif::ProgressBar;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::error::Error;

use crate::utils::{
    get_interface_by_name, get_local_mac_by_interface, get_network_by_interface,
    get_usable_ips_by_network, send_arp_discovery,
};

mod utils;

fn main() -> Result<(), Box<dyn Error>> {
    let ipmac_table = Arc::new(Mutex::new(HashMap::new()));
    let table_for_thread = ipmac_table.clone();
    // get interface name from commad line args
    let iface_name = std::env::args().nth(1).ok_or("Specify interface name")?;

    let iface =
        get_interface_by_name(&iface_name).ok_or("Cannot find interface with specified name")?;
    let local_mac = get_local_mac_by_interface(&iface).ok_or("Cannot get your MAC adress")?;

    let ipv4_network = get_network_by_interface(&iface).ok_or("Cannot get ipv4 network")?;
    let local_ip = ipv4_network.ip();
    // get ip range
    let usable_ips =
        get_usable_ips_by_network(&ipv4_network).ok_or("Cannot get ips in your network")?;

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".into()),
        Err(e) => return Err("Error constructing tx rx channels".into()),
    };

    // RECEIVE IN THREAD
    let rcv_thread = std::thread::spawn(move || {
        loop {
            match rx.next() {
                Ok(packet) => {
                    let eth_packet = EthernetPacket::new(packet).unwrap();

                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply
                                && arp_packet.get_target_hw_addr() == local_mac
                            {
                                let sender_ip = arp_packet.get_sender_proto_addr();
                                let sender_mac = arp_packet.get_sender_hw_addr();

                                let mut table = table_for_thread.lock().unwrap();
                                table.insert(sender_ip, sender_mac);
                            }
                        }
                    }
                }
                Err(e) => panic!("Error: {}", e),
            }
        }
    });
    // send arp packet to all hosts in ips range;
    println!("Sending arp discovery...");
    let bar = ProgressBar::new(usable_ips.len() as u64);
    for ip in usable_ips {
        bar.inc(1);
        send_arp_discovery(&mut *tx, ip, local_ip, local_mac);
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_secs(10));
    // rcv_thread.join().unwrap();

    let final_table = ipmac_table.lock().unwrap();

    println!("Found hosts:");
    for (ip, mac) in final_table.iter() {
        println!("IP:{:<15} MAC: {}", ip, mac);
    }

    Ok(())
}
