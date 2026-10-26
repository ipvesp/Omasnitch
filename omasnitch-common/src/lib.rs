#![no_std]

pub const COMM_LEN: usize = 16;

pub const VERDICT_BLOCK: u8 = 0;
pub const VERDICT_ALLOW: u8 = 1;
pub const VERDICT_ASK: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrafficCounter {
    pub uploaded: u64,
    pub downloaded: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,

    pub port: u16,
    pub family: u16,

    pub protocol: u8,
    pub verdict: u8,
    pub _padding: [u8; 2],

    pub comm: [u8; COMM_LEN],
    pub addr: [u8; 16],
}

impl ConnectEvent {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            uid: 0,
            port: 0,
            family: 0,
            protocol: 0,
            verdict: VERDICT_ALLOW,
            _padding: [0; 2],
            comm: [0; COMM_LEN],
            addr: [0; 16],
        }
    }
}
