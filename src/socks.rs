use std::net::IpAddr;

#[derive(Debug)]
pub enum Address {
    Name(String),
    IP(IpAddr),
}

#[derive(Debug)]
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
}

impl From<Destination> for String {
    fn from(dest: Destination) -> Self {
        match dest.addr {
            Address::Name(name) => {
                format!("{}:{}", name, dest.port)
            }
            Address::IP(ip) => {
                format!("{}:{}", ip.to_string(), dest.port)
            }
        }
    }
}

#[derive(Debug)]
pub enum SOCKS {
    V4,
    V5,
}

#[derive(Debug)]
pub enum SOCKS4Cmd {
    Connect,
    Bind,
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
pub enum SOCKS5Cmd {
    CONNECT,
    BIND,
    UDP,
}

#[derive(Debug)]
pub struct SOCKS5ConnectionRequest {
    pub cmd: SOCKS5Cmd,
    pub dest: Destination,
}
