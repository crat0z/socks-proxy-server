use nom::multi::length_count;
use nom::number::streaming::{be_u128, u8 as number_u8};
use nom::number::streaming::{be_u16, be_u32};
use nom::sequence::tuple;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_until},
    IResult,
};

use nom::Err::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::MyError;
use crate::socks::Address::IP;
use crate::socks::*;

fn take_until_null_consume(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    let (remaining, result) = take_until("\0")(i)?;
    // remaining[0] at this point is start of s, so skip len of s

    Ok((&remaining[1..], result))
}

fn take_u8_len_vec(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    length_count(number_u8, number_u8)(i)
}

fn socks_ver(i: &[u8]) -> IResult<&[u8], SOCKS, MyError> {
    let (remaining, result) = alt((tag(b"\x04"), tag(b"\x05")))(i)?;

    if result[0] == 4 {
        Ok((remaining, SOCKS::V4))
    } else {
        Ok((remaining, SOCKS::V5))
    }
}

fn socks4_cmd(i: &[u8]) -> IResult<&[u8], SOCKS4Cmd, MyError> {
    let (remaining, result) = alt((tag(b"\x01"), tag(b"\x02")))(i)?;
    // 0x01 is connect, 0x02 is bind
    if result[0] == 1 {
        Ok((remaining, SOCKS4Cmd::Connect))
    } else {
        Ok((remaining, SOCKS4Cmd::Bind))
    }
}

fn socks4_dst(i: &[u8]) -> IResult<&[u8], Destination, MyError> {
    let (remaining, port) = be_u16(i)?;
    let (remaining, data) = be_u32(remaining)?;

    let addr = IP(IpAddr::from(Ipv4Addr::from(data)));

    Ok((remaining, Destination { addr, port }))
}

fn socks4_id(i: &[u8]) -> IResult<&[u8], Vec<u8>, MyError> {
    let (remaining, result) = take_until_null_consume(i)?;
    Ok((remaining, result.to_vec()))
}

fn socks4_domain(i: &[u8]) -> IResult<&[u8], &[u8], MyError> {
    take_until_null_consume(i)
}

fn socks5_ver(i: &[u8]) -> IResult<&[u8], (), MyError> {
    let (remaining, _) = tag(b"\x05")(i)?;
    Ok((remaining, ()))
}

fn socks5_auth_methods(i: &[u8]) -> IResult<&[u8], Vec<SOCKS5AuthMethod>, MyError> {
    let (remaining, raw) = take_u8_len_vec(i)?;

    let mut ret = Vec::new();

    for method in raw {
        if method == 0 {
            ret.push(SOCKS5AuthMethod::NoAuth);
        } else if method == 2 {
            ret.push(SOCKS5AuthMethod::UserPass);
        }
    }

    Ok((remaining, ret))
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
        Ok((remaining, SOCKS5Cmd::Connect))
    } else if result[0] == 2 {
        Ok((remaining, SOCKS5Cmd::Bind))
    } else {
        Ok((remaining, SOCKS5Cmd::UDP))
    }
}

fn socks5_rsv(i: &[u8]) -> IResult<&[u8], (), MyError> {
    let (remaining, _) = tag(b"\x00")(i)?;
    Ok((remaining, ()))
}

fn socks5_dst(i: &[u8]) -> IResult<&[u8], Destination, MyError> {
    let (remaining, addrtype) = alt((tag(b"\x01"), tag(b"\x03"), tag(b"\x04")))(i)?;

    if addrtype[0] == 1 {
        let (remaining, data) = be_u32(remaining)?;

        let addr = IP(IpAddr::from(Ipv4Addr::from(data)));

        let (remaining, port) = be_u16(remaining)?;

        Ok((remaining, Destination { addr, port }))
    } else if addrtype[0] == 3 {
        let (remaining, addr) = take_u8_len_vec(remaining)?;

        if let Ok(domain) = String::from_utf8(addr) {
            let (remaining, port) = be_u16(remaining)?;
            Ok((
                remaining,
                Destination {
                    addr: Address::Name(domain),
                    port,
                },
            ))
        } else {
            Err(Error(MyError::Parse))
        }
    } else {
        let (remaining, addr) = be_u128(remaining)?;

        let addr = IP(IpAddr::from(Ipv6Addr::from(addr)));

        let (remaining, port) = be_u16(remaining)?;

        Ok((remaining, Destination { addr, port }))
    }
}

pub fn socks_init(input: &[u8]) -> IResult<&[u8], SOCKSInit, MyError> {
    let (remaining, ver) = socks_ver(input)?;

    match ver {
        SOCKS::V4 => {
            let (remaining, (cmd, mut dest, ident)) =
                tuple((socks4_cmd, socks4_dst, socks4_id))(remaining)?;

            let ip = dest.ipv4_slice().unwrap();

            if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
                let (remaining, domain) = socks4_domain(remaining)?;

                if !remaining.is_empty() {
                    // should be empty
                    return Err(Error(MyError::Parse));
                }

                if let Ok(name) = String::from_utf8(domain.to_vec()) {
                    dest.addr = Address::Name(name);
                } else {
                    return Err(Error(MyError::Parse));
                }
            }

            Ok((remaining, SOCKSInit::V4(SOCKS4Init { cmd, ident, dest })))
        }
        SOCKS::V5 => {
            let (remaining, auth_methods) = socks5_auth_methods(remaining)?;

            if !remaining.is_empty() {
                // should be empty
                return Err(Error(MyError::Parse));
            }

            Ok((remaining, SOCKSInit::V5(SOCKS5Init { auth_methods })))
        }
    }
}

pub fn socks5_auth_request(input: &[u8]) -> IResult<&[u8], SOCKS5AuthRequest, MyError> {
    let (remaining, (ver, id, pw)) = tuple((socks5_auth_ver, socks5_id, socks5_pw))(input)?;

    if !remaining.is_empty() {
        return Err(Error(MyError::Parse));
    }

    Ok((remaining, SOCKS5AuthRequest { ver, id, pw }))
}

pub fn socks5_connection_request(input: &[u8]) -> IResult<&[u8], SOCKS5ConnectRequest, MyError> {
    let (remaining, (_, cmd, _, dest)) =
        tuple((socks5_ver, socks5_cmd, socks5_rsv, socks5_dst))(input)?;

    if !remaining.is_empty() {
        return Err(Error(MyError::Parse));
    }

    Ok((remaining, SOCKS5ConnectRequest { cmd, dest }))
}
