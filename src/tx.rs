use socket::{self, Socket};
use std::{io, mem};

use libc::{c_void, sendto, sockaddr, sockaddr_ll, AF_PACKET, ETH_ALEN};

pub struct Player {
    sock: Socket,
}

impl Player {
    ///gets a socket ready to play frames
    pub fn open_socket(if_name: &str) -> io::Result<Player> {
        let sock = Socket::from_if_name(if_name, socket::AF_PACKET)?;
        Ok(Player { sock })
    }

    ///sends a raw, whole ethernet frame on the socket
    pub fn send_frame(&self, mut frame: &mut [u8]) -> io::Result<()> {
        let mut sa = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: 0,
            sll_ifindex: self.sock.if_index as i32,
            sll_hatype: 519,
            sll_pkttype: 0,
            sll_halen: ETH_ALEN as u8,
            sll_addr: [0; 8], //dest_addr
        };

        //get the size before we change the pointer type otherwise it won't be correct
        let size = mem::size_of_val(&sa);
        //TODO: see if there is another way to do this...
        let addr_ptr = unsafe { mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa) };

        let b = unsafe {
            sendto(
                self.sock.fd,
                &mut frame as *mut _ as *mut c_void,
                mem::size_of_val(&frame),
                0,
                addr_ptr,
                size as u32,
            )
        };
        if b >= 0 {
            return Ok(());
        }
        Err(io::Error::last_os_error())
    }
}
