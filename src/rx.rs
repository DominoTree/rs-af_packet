use std;
use std::io::{self, Error};
use std::mem;

use libc::{
    bind, c_int, c_void, getpid, mmap, poll, pollfd, sockaddr, sockaddr_ll, socklen_t, AF_PACKET,
    ETH_ALEN, ETH_P_IP, MAP_LOCKED, MAP_NORESERVE, MAP_SHARED, POLLERR, POLLIN, PROT_READ,
    PROT_WRITE,
};

use socket::{self, Socket, IFF_PROMISC};

use tpacket3;

//Used digits for these consts, if they were defined differently in C headers I have added that definition in the comments beside them

const PACKET_RX_RING: c_int = 5;
const PACKET_STATISTICS: c_int = 6;
const PACKET_VERSION: c_int = 10;
const PACKET_FANOUT: c_int = 18;

/* https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou */

pub const PACKET_FANOUT_HASH: c_int = 0;
pub const PACKET_FANOUT_LB: c_int = 1;

const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const PACKET_OTHERHOST: u8 = 3;
const PACKET_OUTGOING: u8 = 4;

///Settings to be used to bring up each ring
#[derive(Clone, Debug)]
pub struct RingSettings {
    ///Interface name
    pub if_name: String,
    ///PACKET_FANOUT_HASH will pin flows to individual threads, PACKET_FANOUT_LB will distribute
    ///them across multiple threads
    pub fanout_method: c_int,
    ///Lower-level settings including block size, also enable/disable filling RXHASH in packet data
    pub ring_settings: tpacket3::TpacketReq3,
}

impl Default for RingSettings {
    fn default() -> RingSettings {
        RingSettings {
            if_name: String::from("eth0"),
            fanout_method: PACKET_FANOUT_HASH,
            ring_settings: tpacket3::TpacketReq3::default(),
        }
    }
}

///References a single mmaped ring buffer. Normally one per thread.
#[derive(Clone, Debug)]
pub struct Ring {
    pub socket: Socket,
    mmap: Option<*mut u8>,
    opts: tpacket3::TpacketReq3,
}

///Contains a reference to a block as it exists in the ring buffer, its block descriptor, and a Vec of individual packets in that block.
#[derive(Debug)]
pub struct Block<'a> {
    block_desc: tpacket3::TpacketBlockDesc,
    packets: Vec<RawPacket<'a>>,
    raw_data: &'a mut [u8],
}

///Contains a reference to an individual packet in a block, as well as details about that packet
#[derive(Debug)]
pub struct RawPacket<'a> {
    ///Contains packet details
    pub tpacket3_hdr: tpacket3::Tpacket3Hdr,
    ///Raw packet data including any encapsulations
    pub data: &'a [u8],
}

impl<'a> Block<'a> {
    ///Marks a block as free to be destroyed by the kernel
    #[inline]
    pub fn mark_as_consumed(&mut self) {
        self.raw_data[tpacket3::TP_BLK_STATUS_OFFSET] = tpacket3::TP_STATUS_KERNEL;
        self.raw_data[tpacket3::TP_BLK_STATUS_OFFSET + 1] = 0;
        self.raw_data[tpacket3::TP_BLK_STATUS_OFFSET + 2] = 0;
        self.raw_data[tpacket3::TP_BLK_STATUS_OFFSET + 3] = 0;
    }

    #[inline]
    fn is_ready(&self) -> bool {
        (self.raw_data[tpacket3::TP_BLK_STATUS_OFFSET] & tpacket3::TP_STATUS_USER) != 0
    }

    ///Returns a `Vec` of details and references to raw packets that can be read from the ring buffer
    #[inline]
    pub fn get_raw_packets(&self) -> Vec<RawPacket> {
        //standard block header is 48b

        let mut packets = Vec::<RawPacket>::new();
        let mut next_offset = 48;

        let count = self.block_desc.hdr.num_pkts;
        for x in 0..count {
            let this_offset = next_offset;

            let mut tpacket3_hdr = match tpacket3::get_tpacket3_hdr(&self.raw_data[next_offset..]) {
                Ok(x) => x,
                Err(_) => {
                    continue;
                }
            };

            if x < count - 1 {
                next_offset = this_offset + tpacket3_hdr.1.tp_next_offset as usize;
            } else {
                next_offset = self.raw_data.len();
                tpacket3_hdr.1.tp_next_offset = 0;
            }
            packets.push(RawPacket {
                tpacket3_hdr: tpacket3_hdr.1,
                data: &self.raw_data[this_offset..next_offset],
            });
        }

        packets
    }
}

impl Ring {
    ///Creates a new ring buffer on the specified interface name and puts the interface into promiscuous mode
    pub fn from_if_name(if_name: &str) -> io::Result<Ring> {
        let mut ring = Ring {
            socket: Socket::from_if_name(if_name, socket::PF_PACKET)?,
            mmap: None,
            opts: tpacket3::TpacketReq3::default(),
        };

        ring.socket.set_flag(IFF_PROMISC as u64)?;
        ring.socket
            .setsockopt(PACKET_VERSION, tpacket3::TPACKET_V3)?;
        ring.socket.setsockopt(PACKET_RX_RING, ring.opts.clone())?;
        ring.mmap_rx_ring()?;
        ring.bind_rx_ring()?;
        let fanout = (unsafe { getpid() } & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
        ring.socket.setsockopt(PACKET_FANOUT, fanout)?;
        Ok(ring)
    }

    ///Creates a new ring buffer from the supplied RingSettings struct
    pub fn new(settings: RingSettings) -> io::Result<Ring> {
        //this typecasting sucks :(
        let mut ring = Ring {
            socket: Socket::from_if_name(&settings.if_name, socket::PF_PACKET)?,
            mmap: None,
            opts: settings.ring_settings,
        };

        ring.socket.set_flag(IFF_PROMISC as u64)?;
        ring.socket
            .setsockopt(PACKET_VERSION, tpacket3::TPACKET_V3)?;
        ring.socket.setsockopt(PACKET_RX_RING, ring.opts.clone())?;
        ring.mmap_rx_ring()?;
        ring.bind_rx_ring()?;
        let fanout = (unsafe { getpid() } & 0xFFFF) | (settings.fanout_method << 16);
        ring.socket.setsockopt(PACKET_FANOUT, fanout)?;
        Ok(ring)
    }

    ///Waits for a block to be added to the ring buffer and returns it
    //We're allowing unused_mut here because apps that include this crate may need to control
    //marking blocks as consumed for performance reasons to avoid copies
    #[allow(unused_mut)]
    #[inline]
    pub fn get_block(&mut self) -> Block {
        loop {
            self.wait_for_block();
            //check all blocks in memory space
            for i in 0..self.opts.tp_block_nr {
                if let Some(mut block) = self.get_single_block(i) {
                    if block.is_ready() {
                        return block;
                    }
                }
            }
        }
    }

    fn mmap_rx_ring(&mut self) -> io::Result<()> {
        match unsafe {
            mmap(
                std::ptr::null_mut(),
                (self.opts.tp_block_size * self.opts.tp_block_nr) as usize,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_LOCKED | MAP_NORESERVE,
                self.socket.fd,
                0,
            )
        } as isize
        {
            -1 => Err(io::Error::last_os_error()),
            map => {
                self.mmap = Some(map as *mut u8);
                Ok(())
            }
        }
    }

    fn bind_rx_ring(&mut self) -> io::Result<()> {
        let mut sa = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_IP.to_be() as u16,
            sll_ifindex: self.socket.if_index as c_int,
            sll_hatype: 519,
            sll_pkttype: (PACKET_HOST //can we just use 255 here lol
                | PACKET_BROADCAST
                | PACKET_MULTICAST
                | PACKET_OTHERHOST
                | PACKET_OUTGOING),
            sll_halen: ETH_ALEN as u8,
            sll_addr: [0; 8],
        };

        //get the size before we change the pointer type
        let size = mem::size_of_val(&sa);
        //we have to do this transmute or similar because Linux uses multiple sockaddr_ 
        //family structs and casts them to sockaddr after populating them
        let addr_ptr = unsafe { mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa) };

        match unsafe { bind(self.socket.fd, addr_ptr, size as socklen_t) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[inline]
    fn wait_for_block(&self) {
        let mut pfd = pollfd {
            fd: self.socket.fd,
            events: POLLIN | POLLERR,
            revents: 0,
        };

        unsafe {
            poll(&mut pfd, 1, -1);
        }
    }

    #[inline]
    fn get_single_block<'a>(&mut self, count: u32) -> Option<Block<'a>> {
        //TODO: clean up all this typecasting
        let offset = count as isize * self.opts.tp_block_size as isize;

        let block = unsafe {
            std::slice::from_raw_parts_mut(
                self.mmap?.offset(offset),
                self.opts.tp_block_size as usize,
            )
        };

        let block_desc = match tpacket3::get_tpacket_block_desc(&block[..]) {
            Ok(x) => x,
            Err(_) => {
                return None;
            }
        };

        let blk = Block {
            block_desc: block_desc.1,
            packets: Vec::new(),
            raw_data: &mut block[..],
        };

        Some(blk)
    }
}

unsafe impl Send for Ring {}

///This is very easy because the Linux kernel has its own counters that are reset every time
///getsockopt() is called
#[inline]
pub fn get_rx_statistics(fd: i32) -> Result<tpacket3::TpacketStatsV3, Error> {
    let mut optval = tpacket3::TpacketStatsV3 {
        tp_packets: 0,
        tp_drops: 0,
        tp_freeze_q_cnt: 0,
    };
    socket::get_sock_opt(
        fd,
        PACKET_STATISTICS,
        &(&mut optval as *mut _ as *mut c_void),
    )?;
    Ok(optval)
}
