use std::net::IpAddr;

#[derive(Debug, PartialEq, Clone)]
pub enum Address {
    Name(String),
    IP(IpAddr),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Destination {
    pub addr: Address,
    pub port: u16,
}

impl Destination {
    pub fn ipv4_slice(&self) -> Option<[u8; 4]> {
        if let Address::IP(IpAddr::V4(ip)) = &self.addr {
            Some(ip.octets())
        } else {
            None
        }
    }

    pub fn ipv6_slice(&self) -> Option<[u8; 16]> {
        if let Address::IP(IpAddr::V6(ip)) = &self.addr {
            Some(ip.octets())
        } else {
            None
        }
    }
}

impl From<&Destination> for String {
    fn from(dest: &Destination) -> Self {
        match &dest.addr {
            Address::Name(name) => {
                format!("{}:{}", name, dest.port)
            }
            Address::IP(ip) => {
                format!("{}:{}", ip, dest.port)
            }
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum SOCKS {
    V4 = 4,
    V5 = 5,
}

#[derive(Debug)]
#[repr(u8)]
pub enum SOCKS4Cmd {
    Connect = 1,
    Bind = 2,
}

#[derive(Debug)]
pub struct SOCKS4Init {
    pub cmd: SOCKS4Cmd,
    pub ident: Vec<u8>,
    pub dest: Destination,
}

#[derive(Debug)]
pub struct SOCKS5Init {
    pub auth_methods: Vec<u8>,
}

#[derive(Debug)]
pub enum SOCKSInit {
    V4(SOCKS4Init),
    V5(SOCKS5Init),
}

#[derive(Debug)]
pub struct SOCKS5AuthRequest {
    pub ver: u8,
    pub id: Vec<u8>,
    pub pw: Vec<u8>,
}

#[derive(Debug)]
#[repr(u8)]
pub enum SOCKS5AuthReply {
    Accepted = 0,
    Denied = 255,
}

#[derive(Debug)]
#[repr(u8)]
pub enum SOCKS5Cmd {
    Connect = 1,
    Bind = 2,
    UDP = 3,
}

#[derive(Debug)]
pub struct SOCKS5ConnectRequest {
    pub cmd: SOCKS5Cmd,
    pub dest: Destination,
}

#[derive(Debug)]
#[repr(u8)]
pub enum SOCKS5ConnectReply {
    Accepted = 0,
    Failure = 1,
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TTLExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}
