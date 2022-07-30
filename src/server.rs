use crate::error::MyError;
use crate::socks::Destination;
use crate::socks::SOCKS5AuthMethod;
use clap::{ArgGroup, Parser};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::broadcast;

#[derive(Debug, PartialEq, Eq)]
pub struct User {
    pub user: String,
    pub pass: String,
}

impl FromStr for User {
    type Err = MyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(':');

        if split.clone().count() != 2 {
            Err(MyError::Parse)
        } else {
            Ok(User {
                user: split.next().unwrap().to_owned(),
                pass: split.next().unwrap().to_owned(),
            })
        }
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(group(ArgGroup::new("protos").multiple(true).required(true).args(&["socks4", "socks5"])))]
pub struct Args {
    /// IP to bind to
    #[clap(short, long, default_value = "0.0.0.0")]
    pub ip: IpAddr,

    /// Port to bind to
    #[clap(short, long, default_value_t = 8080u16)]
    pub port: u16,

    /// Enable socks4
    #[clap(long)]
    pub socks4: bool,

    /// Enable socks5
    #[clap(long)]
    pub socks5: bool,

    /// Require authentication. Note that socks4 does not support authentication.
    /// --users and --socks5 are required if authentication is enabled.
    #[clap(short, long, requires_all(&["socks5", "users"]))]
    auth: bool,

    /// user:pass pairs for authentication
    #[clap(short, long, multiple_values(true))]
    users: Option<Vec<User>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Session {
    pub client2server: SocketAddr,
    pub server2client: SocketAddr,
    pub server2remote: SocketAddr,
    pub remote2server: SocketAddr,
    pub destination: Destination,
}

impl Session {
    pub fn new(client: &TcpStream, remote: &TcpStream, dest: Destination) -> Self {
        Session {
            client2server: client.peer_addr().unwrap(),
            server2client: client.local_addr().unwrap(),
            server2remote: remote.local_addr().unwrap(),
            remote2server: remote.peer_addr().unwrap(),
            destination: dest,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    SessionStart(Session),
    SessionEnd(Session),
    Request(Arc<Destination>),
    Reply(Arc<Destination>, Option<Session>),
    AuthMethodReq(Arc<Vec<SOCKS5AuthMethod>>),
    AuthMethodReply(Arc<Vec<SOCKS5AuthMethod>>, Option<SOCKS5AuthMethod>),
    AuthRequst(Arc<User>),
    AuthReply(Arc<User>, bool),
}

pub struct Server {
    active_sessions: Vec<Session>,
    args: Args,
    pub recv: broadcast::Receiver<Message>,
    pub send: broadcast::Sender<Message>,
}

impl Server {
    pub fn new(args: Args) -> Self {
        let (s, r) = broadcast::channel(16);

        Server {
            active_sessions: Vec::new(),
            args,
            recv: r,
            send: s,
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Ok(msg) = self.recv.recv().await {
                match msg {
                    Message::SessionStart(start) => {
                        self.active_sessions.push(start);
                    }
                    Message::SessionEnd(end) => {
                        for (i, v) in self.active_sessions.iter().enumerate() {
                            if end == *v {
                                self.active_sessions.swap_remove(i);
                                break;
                            }
                        }
                    }
                    Message::Request(req) => {
                        let mut found = false;

                        for v in self.active_sessions.iter() {
                            if v.destination == *req {
                                found = true;
                                self.send
                                    .send(Message::Reply(req.clone(), Some(v.clone())))
                                    .unwrap();
                                break;
                            }
                        }

                        if !found {
                            self.send.send(Message::Reply(req, None)).unwrap();
                        }
                    }
                    Message::AuthMethodReq(auths) => {
                        if !self.args.auth && auths.contains(&SOCKS5AuthMethod::NoAuth) {
                            self.send
                                .send(Message::AuthMethodReply(
                                    auths,
                                    Some(SOCKS5AuthMethod::NoAuth),
                                ))
                                .unwrap();
                        } else if self.args.auth && auths.contains(&SOCKS5AuthMethod::UserPass) {
                            self.send
                                .send(Message::AuthMethodReply(
                                    auths,
                                    Some(SOCKS5AuthMethod::UserPass),
                                ))
                                .unwrap();
                        } else {
                            self.send
                                .send(Message::AuthMethodReply(auths, None))
                                .unwrap();
                        }
                    }
                    Message::AuthRequst(req) => {
                        let mut found = false;

                        for user in self.args.users.as_ref().unwrap().iter() {
                            if req.as_ref() == user {
                                self.send
                                    .send(Message::AuthReply(req.clone(), true))
                                    .unwrap();
                                found = true;
                                break;
                            }
                        }

                        if !found {
                            self.send.send(Message::AuthReply(req, false)).unwrap();
                        }
                    }

                    Message::Reply(_, _) => {}
                    Message::AuthMethodReply(_, _) => {}
                    Message::AuthReply(_, _) => {}
                }
            }
        }
    }
}
