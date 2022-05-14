use crate::socks::Destination;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::broadcast;

#[derive(Debug, PartialEq, Clone)]
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
    Request(Destination),
    Reply(Destination, Option<Session>),
}

pub struct Server {
    active_sessions: Vec<Session>,
    pub recv: broadcast::Receiver<Message>,
    pub send: broadcast::Sender<Message>,
}

impl Server {
    pub fn new() -> Self {
        let (s, r) = broadcast::channel(16);

        Server {
            active_sessions: Vec::new(),
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
                            if v.destination == req {
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
                    Message::Reply(_, _) => {}
                }
            }
        }
    }
}
