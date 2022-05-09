extern crate core;

mod client;
mod error;
mod parse;
mod socks;

use futures_util::io::BufReader as IoBufReader;

use std::time::Duration;

use crate::client::Client;
use crate::error::MyError;
use crate::parse::{socks5_auth_request, socks5_connection_request, socks_init};
use crate::socks::{
    SOCKS4Cmd, SOCKS4Init, SOCKS5Cmd, SOCKS5ConnectionRequest, SOCKS5Init, SOCKSInit,
};
use nom_bufreader::AsyncParse;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

async fn handle_socks5(mut client: Client, init: SOCKS5Init) -> Result<(), MyError> {
    // just accept no authentication for now..

    if init.auth_methods.contains(&0u8) {
        let req = timeout(
            Duration::from_secs(120),
            client.parser().parse(socks5_connection_request),
        )
        .await??;

        match req.cmd {
            SOCKS5Cmd::CONNECT => {
                unimplemented!();
            }
            SOCKS5Cmd::BIND => {
                unimplemented!();
            }
            SOCKS5Cmd::UDP => {
                unimplemented!();
            }
        }
    } else {
    }
    Ok(())
}

async fn handle_socks4(mut client: Client, init: SOCKS4Init) -> Result<(), MyError> {
    match init.cmd {
        SOCKS4Cmd::Connect => {
            // apparently timeout is 2 mins for connection establishment
            match timeout(
                Duration::from_secs(120),
                TcpStream::connect(String::from(init.dest)),
            )
            .await?
            {
                Ok(forward) => {
                    // connection accepted
                    client.socks4_connect_reply(true).await?;
                    client.run_connection(forward).await?;

                    Ok(())
                }
                Err(e) => {
                    // connection failed
                    client.socks4_connect_reply(false).await?;
                    Err(MyError::from(e))
                }
            }
        }
        SOCKS4Cmd::Bind => {
            unimplemented!();
        }
    }
}

async fn handle_connection(mut client: Client) -> Result<(), MyError> {
    match client.socks_init().await? {
        SOCKSInit::V4(init) => handle_socks4(client, init).await,
        SOCKSInit::V5(init) => handle_socks5(client, init).await,
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(Client::new(stream)).await {
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
