extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();

    for _ in 0..num_cpus::get() {
        let interface = args[1].clone();
        thread::spawn(move || {
            let mut ring = af_packet::rx::Ring::from_if_name(&interface).unwrap();
            loop {
                let mut block = ring.get_block(); //THIS WILL BLOCK
                for _packet in block.get_raw_packets() {
                    //do something
                }
                block.mark_as_consumed();
            }
        });
    }
    //keep main thread alive
    loop {
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
