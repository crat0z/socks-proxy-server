#[derive(Debug)]
pub enum IP {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(String),
}

#[derive(Debug)]
pub struct Destination {
    pub ip: IP,
    pub port: u16,
}

impl From<Destination> for String {
    fn from(dest: Destination) -> Self {
        match dest.ip {
            IP::V4(ip) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], dest.port)
            }
            IP::Name(name) => {
                format!("{}:{}", name, dest.port)
            }
            IP::V6(ip) => {
                let mut s = String::new();

                for i in ip.iter() {
                    // this is gross
                    s += &*format!("{:x}:", i);
                }

                format!("{}{}", s, dest.port)
            }
        }
    }
}

#[derive(Debug)]
pub struct SOCKS4Init {
    pub cmd: u8,
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
pub struct SOCKS5ConnectionRequest {
    pub cmd: u8,
    pub dest: Destination,
}
