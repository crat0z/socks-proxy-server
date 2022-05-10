use crate::socks::{SOCKS5AuthReply, SOCKS5AuthRequest, SOCKS5ConnectReply};
use crate::{
    socks5_auth_request, socks5_connection_request, socks_init, IoBufReader, MyError,
    SOCKS5ConnectRequest, SOCKSInit,
};
use bytes::{BufMut, BytesMut};
use nom_bufreader::AsyncParse;
use replace_with::replace_with_or_abort;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::{copy, split, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

#[derive(Debug)]
pub enum Stream {
    Default(TcpStream),
    Parsing(IoBufReader<Compat<TcpStream>>),
    Split(ReadHalf<TcpStream>, WriteHalf<TcpStream>),
}

impl Stream {
    fn new(s: TcpStream) -> Self {
        Stream::Default(s)
    }

    fn parser(&mut self) -> &mut IoBufReader<Compat<TcpStream>> {
        replace_with_or_abort(self, |self_| match self_ {
            Stream::Default(def) => Stream::Parsing(IoBufReader::new(def.compat())),
            Stream::Parsing(par) => Stream::Parsing(par),
            Stream::Split(r, w) => {
                let combined = r.unsplit(w);
                Stream::Parsing(IoBufReader::new(combined.compat()))
            }
        });

        if let Stream::Parsing(par) = self {
            par
        } else {
            unreachable!();
        }
    }

    fn split(&mut self) -> (&mut ReadHalf<TcpStream>, &mut WriteHalf<TcpStream>) {
        replace_with_or_abort(self, |self_| match self_ {
            Stream::Default(def) => {
                let (r, w) = split(def);
                Stream::Split(r, w)
            }
            Stream::Parsing(par) => {
                let (r, w) = split(par.into_inner().into_inner());
                Stream::Split(r, w)
            }
            Stream::Split(r, w) => Stream::Split(r, w),
        });

        if let Stream::Split(r, w) = self {
            (r, w)
        } else {
            unreachable!();
        }
    }

    fn default(&mut self) -> &mut TcpStream {
        replace_with_or_abort(self, |self_| match self_ {
            Stream::Default(def) => Stream::Default(def),
            Stream::Parsing(par) => Stream::Default(par.into_inner().into_inner()),
            Stream::Split(r, w) => {
                let combined = r.unsplit(w);
                Stream::Default(combined)
            }
        });

        if let Stream::Default(def) = self {
            def
        } else {
            unreachable!();
        }
    }
}

#[derive(Debug)]
pub struct Client {
    connection: Stream,
}

impl Client {
    pub fn new(s: TcpStream) -> Self {
        Client {
            connection: Stream::new(s),
        }
    }

    async fn send(&mut self, msg: &[u8]) -> Result<(), MyError> {
        self.connection.default().write(msg).await?;
        Ok(())
    }

    pub async fn run_connection(&mut self, server: TcpStream) -> Result<(), MyError> {
        let (cr, cw) = self.connection.split();
        let (mut sr, mut sw) = split(server);

        let client_to_server = async {
            copy(cr, &mut sw).await?;
            sw.shutdown().await
        };

        let server_to_client = async {
            copy(&mut sr, cw).await?;
            cw.shutdown().await
        };

        tokio::try_join!(client_to_server, server_to_client)?;

        Ok(())
    }

    pub async fn socks_init(&mut self) -> Result<SOCKSInit, MyError> {
        match timeout(
            Duration::from_secs(5),
            self.connection.parser().parse(socks_init),
        )
        .await?
        {
            Ok(r) => Ok(r),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn socks5_auth_request(&mut self) -> Result<SOCKS5AuthRequest, MyError> {
        match timeout(
            Duration::from_secs(120),
            self.connection.parser().parse(socks5_auth_request),
        )
        .await?
        {
            Ok(r) => Ok(r),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn socks5_connection_request(&mut self) -> Result<SOCKS5ConnectRequest, MyError> {
        match timeout(
            Duration::from_secs(120),
            self.connection.parser().parse(socks5_connection_request),
        )
        .await?
        {
            Ok(r) => Ok(r),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn socks4_connect_reply(&mut self, accepted: bool) -> Result<(), MyError> {
        let mut msg = [0u8; 8];

        if accepted {
            msg[1] = 0x5A;
        } else {
            msg[1] = 0x5B;
        }

        self.send(msg.as_slice()).await
    }

    pub async fn socks5_auth_reply(&mut self, r: SOCKS5AuthReply) -> Result<(), MyError> {
        let msg = [5u8, r as u8];
        self.send(msg.as_slice()).await
    }

    pub async fn socks5_connection_reply(
        &mut self,
        r: SOCKS5ConnectReply,
        ip: Option<IpAddr>,
        port: Option<u16>,
    ) -> Result<(), MyError> {
        let ip = ip.unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        let port = port.unwrap_or(0);
        match ip {
            IpAddr::V4(ip) => {
                let mut buf = BytesMut::with_capacity(10);
                buf.extend([5u8, r as u8, 0, 1]);
                buf.extend(ip.octets());
                buf.put_u16(port);
                self.send(&buf).await
            }
            IpAddr::V6(ip) => {
                let mut buf = BytesMut::with_capacity(22);
                buf.extend([5u8, r as u8, 0, 3]);
                buf.extend(ip.octets());
                buf.put_u16(port);
                self.send(&buf).await
            }
        }
    }
}
