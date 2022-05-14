#![feature(io_error_more)]
#![feature(io_error_uncategorized)]

mod client;
mod error;
mod parse;
mod server;
mod socks;

use crate::client::Client;
use crate::error::MyError;
use crate::server::{Message, Server, Session};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    let mut server = Server::new();

    let s = server.send.clone();

    tokio::spawn(async move {
        server.run().await;
    });

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let send = s.clone();
                tokio::spawn(async move {
                    if let Err(e) = Client::new(stream, send).handle_connection().await {
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
