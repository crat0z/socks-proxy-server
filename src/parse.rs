use nom::multi::length_count;
use nom::number::streaming::be_u16;
use nom::number::streaming::u8 as number_u8;
use nom::sequence::tuple;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take, take_until},
    IResult,
};

use crate::error::MyError;
use crate::socks::*;

fn take_until_null_consume(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    let (remaining, result) = take_until("\0")(i)?;
    // remaining[0] at this point is start of s, so skip len of s

    Ok((&remaining[1..], result))
}

fn take_u8_len_vec(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    length_count(number_u8, number_u8)(i)
}

fn socks_ver(i: &[u8]) -> IResult<&[u8], u8, MyError> {
    let (remaining, result) = alt((tag(b"\x04"), tag(b"\x05")))(i)?;
    Ok((remaining, result[0]))
}

fn socks4_cmd(i: &[u8]) -> IResult<&[u8], SOCKS4Cmd, MyError> {
    let (remaining, result) = alt((tag(b"\x01"), tag(b"\x02")))(i)?;
    // 0x01 is connect, 0x02 is bind
    if result[0] == 1 {
        Ok((remaining, SOCKS4Cmd::CONNECT))
    } else {
        Ok((remaining, SOCKS4Cmd::BIND))
    }
}

fn socks4_dstport(i: &[u8]) -> IResult<&[u8], u16, MyError> {
    be_u16(i)
}

fn socks4_dstip(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    take(4u8)(i)
}

fn socks4_id(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    take_until_null_consume(i)
}

fn socks4_domain(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    take_until_null_consume(i)
}

fn socks5_ver(i: &[u8]) -> IResult<&[u8], (), MyError> {
    let (remaining, _) = tag(b"\x05")(i)?;
    Ok((remaining, ()))
}

fn socks5_auth_methods(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    take_u8_len_vec(i)
}

fn socks5_auth_ver(i: &[u8]) -> IResult<&[u8], u8, MyError> {
    number_u8(i)
}

fn socks5_id(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    take_u8_len_vec(i)
}

fn socks5_pw(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    take_u8_len_vec(i)
}

fn socks5_cmd(i: &[u8]) -> IResult<&[u8], SOCKS5Cmd, MyError> {
    let (remaining, result) = alt((tag(b"\x01"), tag(b"\x02"), tag(b"\x03")))(i)?;

    // 1 is connect, 2 is bind, 3 is udp
    if result[0] == 1 {
        Ok((remaining, SOCKS5Cmd::CONNECT))
    } else if result[0] == 2 {
        Ok((remaining, SOCKS5Cmd::BIND))
    } else {
        Ok((remaining, SOCKS5Cmd::UDP))
    }
}

fn socks5_rsv(i: &[u8]) -> IResult<&[u8], (), MyError> {
    let (remaining, _) = tag(b"\x00")(i)?;
    Ok((remaining, ()))
}

fn socks5_dstaddr(i: &[u8]) -> IResult<&[u8], IP, MyError> {
    let (remaining, addrtype) = alt((tag(b"\x01"), tag(b"\x03"), tag(b"\x04")))(i)?;

    // ipv4
    if addrtype[0] == 1 {
        let (remaining, addr) = take(4u8)(remaining)?;
        Ok((remaining, IP::V4(<[u8; 4]>::try_from(addr).unwrap())))
    } else if addrtype[0] == 3 {
        let (remaining, addr) = take_u8_len_vec(remaining)?;

        if let Ok(domain) = String::from_utf8(addr) {
            Ok((remaining, IP::Name(domain)))
        } else {
            panic!();
        }
    } else {
        let (remaining, addr) = take(16u8)(remaining)?;
        Ok((remaining, IP::V6(<[u8; 16]>::try_from(addr).unwrap())))
    }
}

fn socks5_dstport(i: &[u8]) -> IResult<&[u8], u16, MyError> {
    be_u16(i)
}

pub fn socks_init(input: &[u8]) -> IResult<&[u8], SOCKSInit, MyError> {
    let (remaining, ver) = socks_ver(input)?;

    if ver == 4 {
        let (remaining, (cmd, port, ip, id)) =
            tuple((socks4_cmd, socks4_dstport, socks4_dstip, socks4_id))(remaining)?;

        let dest;

        if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
            let (remaining, domain) = socks4_domain(remaining)?;

            if !remaining.is_empty() {
                // should be empty
                panic!();
            }

            if let Ok(name) = String::from_utf8(domain.to_vec()) {
                dest = Destination {
                    ip: IP::Name(name),
                    port,
                };
            } else {
                panic!();
            }
        } else {
            dest = Destination {
                ip: IP::V4(<[u8; 4]>::try_from(ip).unwrap()),
                port,
            }
        }

        Ok((
            remaining,
            SOCKSInit::V4(SOCKS4Init {
                cmd,
                ident: Vec::from(id),
                dest,
            }),
        ))
    } else {
        let (remaining, auth_methods) = socks5_auth_methods(remaining)?;

        if !remaining.is_empty() {
            // should be empty
            panic!();
        }

        Ok((remaining, SOCKSInit::V5(SOCKS5Init { auth_methods })))
    }
}

pub fn socks5_auth_request(input: &[u8]) -> IResult<&[u8], SOCKS5AuthRequest, MyError> {
    let (remaining, (ver, id, pw)) = tuple((socks5_auth_ver, socks5_id, socks5_pw))(input)?;

    if !remaining.is_empty() {
        panic!();
    }

    Ok((remaining, SOCKS5AuthRequest { ver, id, pw }))
}

pub fn socks5_connection_request(input: &[u8]) -> IResult<&[u8], SOCKS5ConnectionRequest, MyError> {
    let (remaining, (_, cmd, _, ip, port)) = tuple((
        socks5_ver,
        socks5_cmd,
        socks5_rsv,
        socks5_dstaddr,
        socks5_dstport,
    ))(input)?;

    if !remaining.is_empty() {
        panic!();
    }

    let dest = Destination { ip, port };

    Ok((remaining, SOCKS5ConnectionRequest { cmd, dest }))
}
