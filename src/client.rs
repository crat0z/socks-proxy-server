use crate::parse::{socks5_auth_request, socks5_connection_request, socks_init};
use crate::server::User;
use crate::socks::{
    SOCKS4Cmd, SOCKS4Init, SOCKS5AuthMethod, SOCKS5AuthReply, SOCKS5AuthRequest, SOCKS5Cmd,
    SOCKS5ConnectReply, SOCKS5ConnectRequest, SOCKS5Init, SOCKSInit,
};
use crate::{Message, MyError, Session};
use bytes::{BufMut, BytesMut};
use futures_util::io::BufReader as IoBufReader;
use nom_bufreader::AsyncParse;
use replace_with::replace_with_or_abort;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy, split, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::Sender;
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
    sender: Sender<Message>,
}

impl Client {
    pub fn new(s: TcpStream, sender: Sender<Message>) -> Self {
        Client {
            connection: Stream::new(s),
            sender,
        }
    }

    pub fn default(&mut self) -> &mut TcpStream {
        self.connection.default()
    }

    async fn send(&mut self, msg: &[u8]) -> Result<(), MyError> {
        self.connection.default().write_all(msg).await?;
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

    pub async fn socks4_connect_reply(
        &mut self,
        accepted: bool,
        ip: Option<Ipv4Addr>,
        port: Option<u16>,
    ) -> Result<(), MyError> {
        let mut msg = BytesMut::with_capacity(8);

        msg.put_u8(0);
        if accepted {
            msg.put_u8(0x5A);
        } else {
            msg.put_u8(0x5B);
        }

        if ip.is_some() {
            let ip = ip.unwrap();
            let port = port.unwrap();
            msg.extend(ip.octets());
            msg.put_u16(port);
        } else {
            msg.extend([0, 0, 0, 0, 0, 0]);
        }

        self.send(&msg).await
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
        let ip = ip.unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
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

    pub async fn handle_connection(&mut self, socks4: bool, socks5: bool) -> Result<(), MyError> {
        match self.socks_init().await? {
            SOCKSInit::V4(init) => {
                if socks4 {
                    self.handle_socks4(init).await
                } else {
                    Ok(())
                }
            }
            SOCKSInit::V5(init) => {
                if socks5 {
                    self.handle_socks5(init).await
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn handle_socks4(&mut self, init: SOCKS4Init) -> Result<(), MyError> {
        match init.cmd {
            SOCKS4Cmd::Connect => {
                // apparently timeout is 2 mins for connection establishment
                match timeout(
                    Duration::from_secs(120),
                    TcpStream::connect(String::from(&init.dest)),
                )
                .await?
                {
                    Ok(forward) => {
                        // connection accepted
                        self.socks4_connect_reply(true, None, None).await?;
                        self.run_connection(forward).await?;

                        Ok(())
                    }
                    Err(e) => {
                        // connection failed
                        self.socks4_connect_reply(false, None, None).await?;
                        Err(e.into())
                    }
                }
            }
            SOCKS4Cmd::Bind => {
                let addr_info = {
                    let mut receiver = self.sender.subscribe();

                    let orig_dest = Arc::new(init.dest);

                    self.sender
                        .send(Message::Request(orig_dest.clone()))
                        .unwrap();

                    loop {
                        if let Ok(Message::Reply(dest, session)) = receiver.recv().await {
                            if dest == orig_dest {
                                break session;
                            }
                        }
                    }
                };

                if addr_info.is_none() {
                    self.socks4_connect_reply(false, None, None).await?;
                    return Ok(());
                }

                let addr_info = addr_info.unwrap();

                match addr_info.server2remote.ip() {
                    IpAddr::V4(ip) => {
                        match TcpListener::bind(SocketAddr::new(ip.into(), 0)).await {
                            Ok(listener) => {
                                let listen_addr = listener.local_addr().unwrap();

                                self.socks4_connect_reply(true, Some(ip), Some(listen_addr.port()))
                                    .await?;

                                match listener.accept().await {
                                    Ok((stream, _)) => {
                                        self.socks4_connect_reply(true, None, None).await?;

                                        self.run_connection(stream).await?;
                                    }
                                    Err(_) => {
                                        self.socks4_connect_reply(false, None, None).await?;
                                    }
                                }
                            }
                            Err(_) => {
                                self.socks4_connect_reply(false, None, None).await?;
                            }
                        }
                    }
                    IpAddr::V6(_) => {
                        // only support ipv4
                        self.socks4_connect_reply(false, None, None).await?;
                        return Ok(());
                    }
                }

                Ok(())
            }
        }
    }

    async fn handle_socks5(&mut self, init: SOCKS5Init) -> Result<(), MyError> {
        let auth_method = {
            let auth_methods = Arc::new(init.auth_methods);

            let mut receiver = self.sender.subscribe();

            self.sender
                .send(Message::AuthMethodReq(auth_methods.clone()))
                .unwrap();

            let reply = {
                loop {
                    if let Ok(Message::AuthMethodReply(methods, selected)) = receiver.recv().await {
                        if methods == auth_methods {
                            break selected;
                        }
                    }
                }
            };

            if reply.is_none() {
                self.socks5_auth_reply(SOCKS5AuthReply::Denied).await?;
                return Ok(());
            }

            reply.unwrap()
        };

        match auth_method {
            SOCKS5AuthMethod::NoAuth => {
                self.socks5_auth_reply(SOCKS5AuthReply::Accepted).await?;
            }
            SOCKS5AuthMethod::UserPass => {
                self.socks5_auth_reply(SOCKS5AuthReply::UserPass).await?;

                let client_auth = self.socks5_auth_request().await?;

                if let (Ok(user), Ok(pass)) = (
                    String::from_utf8(client_auth.id),
                    String::from_utf8(client_auth.pw),
                ) {
                    let user = Arc::new(User { user, pass });

                    let mut receiver = self.sender.subscribe();
                    self.sender.send(Message::AuthRequst(user.clone())).unwrap();

                    loop {
                        if let Ok(Message::AuthReply(req, accepted)) = receiver.recv().await {
                            if req == user {
                                if accepted {
                                    self.socks5_auth_reply(SOCKS5AuthReply::Accepted).await?;
                                    break;
                                }
                                self.socks5_auth_reply(SOCKS5AuthReply::Denied).await?;
                                return Ok(());
                            }
                        }
                    }
                } else {
                    self.socks5_auth_reply(SOCKS5AuthReply::Denied).await?;
                }
            }
        };

        let req = self.socks5_connection_request().await?;

        return match req.cmd {
            SOCKS5Cmd::Connect => {
                match timeout(
                    Duration::from_secs(120),
                    TcpStream::connect(String::from(&req.dest)),
                )
                .await?
                {
                    Ok(server) => {
                        let msg = Session::new(self.default(), &server, req.dest);

                        self.sender
                            .send(Message::SessionStart(msg.clone()))
                            .unwrap();

                        let socket_addr = server.local_addr()?;
                        self.socks5_connection_reply(
                            SOCKS5ConnectReply::Accepted,
                            Some(socket_addr.ip()),
                            Some(socket_addr.port()),
                        )
                        .await?;

                        self.run_connection(server).await?;

                        self.sender.send(Message::SessionEnd(msg)).unwrap();
                        Ok(())
                    }
                    Err(e) => {
                        // should match on err.kind() instead

                        let reply = match e.kind() {
                            ErrorKind::ConnectionRefused => SOCKS5ConnectReply::ConnectionRefused,
                            ErrorKind::HostUnreachable => SOCKS5ConnectReply::HostUnreachable,
                            ErrorKind::NetworkUnreachable => SOCKS5ConnectReply::NetworkUnreachable,

                            _ => SOCKS5ConnectReply::Failure,
                        };

                        self.socks5_connection_reply(reply, None, None).await?;

                        Err(e.into())
                    }
                }
            }
            SOCKS5Cmd::Bind => {
                let addr_info = {
                    let mut receiver = self.sender.subscribe();

                    let orig_dest = Arc::new(req.dest);
                    self.sender
                        .send(Message::Request(orig_dest.clone()))
                        .unwrap();

                    loop {
                        if let Ok(Message::Reply(dest, session)) = receiver.recv().await {
                            if dest == orig_dest {
                                break session;
                            }
                        }
                    }
                };

                if addr_info.is_none() {
                    self.socks5_connection_reply(SOCKS5ConnectReply::Failure, None, None)
                        .await?;

                    return Ok(());
                }

                // bind to IP which remote can connect to

                match TcpListener::bind(SocketAddr::new(addr_info.unwrap().server2remote.ip(), 0))
                    .await
                {
                    Ok(listener) => {
                        let listen_addr = listener.local_addr().unwrap();

                        self.socks5_connection_reply(
                            SOCKS5ConnectReply::Accepted,
                            Some(listen_addr.ip()),
                            Some(listen_addr.port()),
                        )
                        .await?;

                        match listener.accept().await {
                            Ok((stream, socket)) => {
                                self.socks5_connection_reply(
                                    SOCKS5ConnectReply::Accepted,
                                    Some(socket.ip()),
                                    Some(socket.port()),
                                )
                                .await?;

                                self.run_connection(stream).await?;
                            }
                            Err(_) => {
                                self.socks5_connection_reply(
                                    SOCKS5ConnectReply::Failure,
                                    None,
                                    None,
                                )
                                .await?;
                            }
                        }
                    }
                    Err(_) => {
                        self.socks5_connection_reply(SOCKS5ConnectReply::Failure, None, None)
                            .await?;
                    }
                }

                Ok(())
            }
            SOCKS5Cmd::Udp => {
                self.socks5_connection_reply(SOCKS5ConnectReply::CommandNotSupported, None, None)
                    .await?;
                Ok(())
            }
        };
    }
}
