#![feature(io_error_more)]
#![feature(io_error_uncategorized)]

mod client;
mod error;
mod parse;
mod server;
mod socks;

use crate::client::Client;
use crate::error::MyError;
use crate::server::Args;
use crate::server::{Message, Server, Session};
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let args: Args = Args::parse();

    dbg!(&args);

    let socks4 = args.socks4;
    let socks5 = args.socks5;

    let socket = SocketAddr::new(args.ip, args.port);

    let listener = TcpListener::bind(socket)
        .await
        .expect("Unable to bind to socket");

    let mut server = Server::new(args);

    let s = server.send.clone();

    tokio::spawn(async move {
        server.run().await;
    });

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let send = s.clone();
                tokio::spawn(async move {
                    if let Err(e) = Client::new(stream, send)
                        .handle_connection(socks4, socks5)
                        .await
                    {
                        dbg!("{}", e);
                    }
                });
            }
            Err(e) => {
                println!("couldn't connect {}", e);
            }
        }
    }
}
