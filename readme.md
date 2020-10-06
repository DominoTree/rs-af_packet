# High-Performance AF_PACKET bindings for Rust

[![Crates.io](https://img.shields.io/crates/v/af_packet.svg)](https://crates.io/crates/af_packet)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![af_packet](https://docs.rs/af_packet/badge.svg)](https://docs.rs/af_packet)

This library is intended to provide an efficient, safe, and ergonomic way of reading raw packet data on an interface across multiple threads. Its primary intended use is for network security and monitoring applications, in conjunction with crates like `nom` (https://github.com/Geal/nom) to build protocol decoders and more complex analysis engines.

## A multi-threaded raw receiver in ~40 lines of code

The Linux kernel provides flow balancing based on a hashed tuple so threads do not need to communicate with each other to do flow reassembly. This behavior is, however, configurable.  A full multithreaded DNS sniffer in ~70 lines of code can be seen at (https://github.com/DominoTree/rs-dns-sniffer/blob/master/src/main.rs). It can decode over 120,000 DNS messages per second on an eight-core machine without dropping any frames, and has been tested beyond 1,500,000 records per second.

```rust
extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

fn main() {
    //get args
    let args: Vec<String> = env::args().collect();
    
    //create a vec for file descriptors to poll for statistics
    let mut fds = Vec::<i32>::new();

    //spawn one thread per CPU
    for _ in 0..num_cpus::get() {
        let interface = args[1].clone();
        
        //open an mmap()ed ring buffer for this thread
        let mut ring = af_packet::Ring::from_if_name(&interface).unwrap();
        
        //store the fd from the ring to get stats later
        fds.push(ring.fd);
        
        thread::spawn(move || {
            //move struct into the thread
            //receive blocks and process them
            loop {
                let mut block = ring.get_block();
                for _packet in block.get_raw_packets() {
                    //process frame data here
                }
                block.mark_as_consumed();
            }
        });
    }

    //Below is to print statistics only
    let mut packets: u64 = 0;
    let mut drops: u64 = 0;

    loop {
        let mut stats: (u64, u64) = (0, 0);
        for fd in &fds {
            let ring_stats = af_packet::get_rx_statistics(*fd).unwrap();
            stats.0 += ring_stats.tp_drops as u64;
            stats.1 += ring_stats.tp_packets as u64;
        }
        drops += stats.0;
        packets += stats.1;
        eprintln!("{} frames received per second, {} dropped. {} total drops of {} total packets ({}%)", stats.1, stats.0, drops, packets, format!("{:.*}", 4, drops as f64 / packets as f64 * 100 as f64));
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
```

*Based on work by Tom Karpiniec (http://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html) and Herman Radtke (http://hermanradtke.com/2016/03/17/unions-rust-ffi.html)*
