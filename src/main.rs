use futures_util::io::BufReader as IoBufReader;
use std::time::Duration;

use nom::combinator::opt;
use nom::number::streaming::be_u16;
use nom::sequence::tuple;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take, take_until},
    IResult,
};
use nom_bufreader::async_bufreader::BufReader;
use nom_bufreader::AsyncParse;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;
fn socks_ver(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    alt((tag(b"\x04"), tag(b"\x05")))(i)
}

fn socks4_cmd(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    alt((tag(b"\x01"), tag(b"\x02")))(i)
}

fn socks4_dstport(i: &[u8]) -> IResult<&[u8], u16, ()> {
    be_u16(i)
}

fn socks4_dstip(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    take(4u8)(i)
}

fn take_until_null_consume(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    let (remaining, result) = take_until("\0")(i)?;
    // remaining[0] at this point is start of s, so skip len of s

    Ok((&remaining[1..], result))
}

fn socks4_id(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    take_until_null_consume(i)
}

fn socks4_domain(i: &[u8]) -> IResult<&[u8], &[u8], ()> {
    take_until_null_consume(i)
}

#[derive(Debug)]
enum IP {
    Raw([u8; 4]),
    Name(String),
}

#[derive(Debug)]
struct Destination {
    ip: IP,
    port: u16,
}

impl From<Destination> for String {
    fn from(dest: Destination) -> Self {
        match dest.ip {
            IP::Raw(ip) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], dest.port)
            }
            IP::Name(name) => {
                format!("{}:{}", name, dest.port)
            }
        }
    }
}

#[derive(Debug)]
struct SOCKS4Init {
    cmd: u8,
    ident: Vec<u8>,
    dest: Destination,
}

#[derive(Debug)]
struct SOCKS5Init {}

#[derive(Debug)]
enum SOCKSInit {
    V4(SOCKS4Init),
    V5(SOCKS5Init),
}

fn socks_init(input: &[u8]) -> IResult<&[u8], SOCKSInit, ()> {
    let (remaining, ver) = socks_ver(input)?;

    if ver[0] == 4 {
        let (remaining, (cmd, port, ip, id)) =
            tuple((socks4_cmd, socks4_dstport, socks4_dstip, socks4_id))(remaining)?;

        let dest;

        if !remaining.is_empty() {
            // socks4a
            let (remaining, domain) = socks4_domain(remaining)?;

            if !remaining.is_empty() {
                // should be empty
                panic!();
            }

            if let Ok(domain) = String::from_utf8(domain.to_vec()) {
                dest = Destination {
                    ip: IP::Name(domain),
                    port,
                };
            } else {
                panic!();
            }
        } else {
            dest = Destination {
                ip: IP::Raw(<[u8; 4]>::try_from(ip).unwrap()),
                port,
            }
        }

        Ok((
            remaining,
            SOCKSInit::V4(SOCKS4Init {
                cmd: cmd[0],
                ident: Vec::from(id),
                dest,
            }),
        ))
    } else {
        unimplemented!();
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    let mut i = BufReader::new(IoBufReader::new(
        listener.accept().await.unwrap().0.compat(),
    ));

    let msg = timeout(Duration::from_secs(5), i.parse(socks_init))
        .await
        .unwrap();

    dbg!(msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ver() {
        let mut t = [4u8];

        assert_eq!(socks_ver(&t), Ok(([].as_slice(), [4u8].as_slice())));

        //assert_eq!(socks_ver(&t), Err(([1u8], []), ErrorKind::Tag))
    }
}
