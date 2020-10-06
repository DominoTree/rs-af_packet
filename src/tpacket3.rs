use libc::{c_int, c_uint};
use nom::number::complete::{le_u16, le_u32, le_u64};

pub const TP_STATUS_KERNEL: u8 = 0;
pub const TP_STATUS_USER: u8 = 1;
//const TP_STATUS_COPY: u8 = 1 << 1;
//const TP_STATUS_LOSING: u8 = 1 << 2;
//const TP_STATUS_CSUMNOTREADY: u8 = 1 << 3;
//const TP_STATUS_CSUM_VALID: u8 = 1 << 7;

pub const TPACKET_V3: c_int = 2;

const TP_FT_REQ_FILL_RXHASH: c_uint = 1; //0x1;

pub const TP_BLK_STATUS_OFFSET: usize = 8;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketStatsV3 {
    pub tp_packets: c_uint,
    pub tp_drops: c_uint,
    pub tp_freeze_q_cnt: c_uint,
}

#[derive(Clone, Debug)]
#[repr(C)]
///Lower-level settings about ring buffer allocation and behavior
///tp_frame_size * tp_frame_nr must equal tp_block_size * tp_block_nr
pub struct TpacketReq3 {
    ///Block size of ring
    pub tp_block_size: c_uint,
    ///Number of blocks allocated for ring
    pub tp_block_nr: c_uint,
    ///Frame size of ring
    pub tp_frame_size: c_uint,
    ///Number of frames in ring
    pub tp_frame_nr: c_uint,
    ///Timeout in milliseconds
    pub tp_retire_blk_tov: c_uint,
    ///Offset to private data area
    pub tp_sizeof_priv: c_uint,
    ///Controls whether RXHASH is filled - 0 for false, 1 for true
    pub tp_feature_req_word: c_uint,
}

#[derive(Clone, Debug)]
pub struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    pub hdr: TpacketBDHeader,
}

#[derive(Clone, Debug)]
pub struct TpacketBDHeader {
    block_status: u32,
    pub num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBDTS,
    ts_last_pkt: TpacketBDTS,
}

#[derive(Clone, Debug)]
struct TpacketBDTS {
    ts_sec: u32,
    ts_nsec: u32,
}

///Contains details about individual packets in a block
#[derive(Clone, Debug)]
pub struct Tpacket3Hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: TpacketHdrVariant1,
    //pub tp_padding: [u8; 8],
}

///Contains VLAN tags and RX Hash value (if enabled)
#[derive(Clone, Debug)]
pub struct TpacketHdrVariant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    tp_padding: u16,
}

impl Default for TpacketReq3 {
    fn default() -> TpacketReq3 {
        TpacketReq3 {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
            tp_retire_blk_tov: 100,
            tp_sizeof_priv: 0,
            tp_feature_req_word: TP_FT_REQ_FILL_RXHASH,
        }
    }
}

#[inline]
named!(
    pub get_tpacket_block_desc<TpacketBlockDesc>,
    do_parse!(
        version: le_u32 >> offset_to_priv: le_u32 >> hdr: get_tpacket_bd_header
            >> (TpacketBlockDesc {
                version,
                offset_to_priv,
                hdr
            })
    )
);

#[inline]
named!(
    get_tpacket_bd_header<TpacketBDHeader>,
    do_parse!(
        block_status: le_u32
            >> num_pkts: le_u32
            >> offset_to_first_pkt: le_u32
            >> blk_len: le_u32
            >> seq_num: le_u64
            >> ts_first_pkt: get_tpacket_bdts
            >> ts_last_pkt: get_tpacket_bdts
            >> (TpacketBDHeader {
                block_status,
                num_pkts,
                offset_to_first_pkt,
                blk_len,
                seq_num,
                ts_first_pkt,
                ts_last_pkt
            })
    )
);

#[inline]
named!(
    get_tpacket_bdts<TpacketBDTS>,
    do_parse!(ts_sec: le_u32 >> ts_nsec: le_u32 >> (TpacketBDTS { ts_sec, ts_nsec }))
);

#[inline]
named!(
    get_tpacket_hdr_variant1<TpacketHdrVariant1>,
    do_parse!(
        tp_rxhash: le_u32
            >> tp_vlan_tci: le_u32
            >> tp_vlan_tpid: le_u16
            >> tp_padding: le_u16
            >> (TpacketHdrVariant1 {
                tp_rxhash,
                tp_vlan_tci,
                tp_vlan_tpid,
                tp_padding
            })
    )
);

#[inline]
named!(
    pub get_tpacket3_hdr<Tpacket3Hdr>,
    do_parse!(
        tp_next_offset: le_u32 >> tp_sec: le_u32 >> tp_nsec: le_u32 >> tp_snaplen: le_u32
            >> tp_len: le_u32 >> tp_status: le_u32 >> tp_mac: le_u16 >> tp_net: le_u16
            >> hv1: get_tpacket_hdr_variant1 >> (Tpacket3Hdr {
            tp_next_offset,
            tp_sec,
            tp_nsec,
            tp_snaplen,
            tp_len,
            tp_status,
            tp_mac,
            tp_net,
            hv1
        })
    )
);
