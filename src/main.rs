mod error;
mod parse;
mod socks;

use futures_util::io::BufReader as IoBufReader;

use std::time::Duration;

use crate::error::MyError;
use crate::parse::socks_init;
use crate::socks::{SOCKS4Init, SOCKS5Init, SOCKSInit};
use nom_bufreader::async_bufreader::BufReader;
use nom_bufreader::AsyncParse;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;

async fn handle_socks5(stream: TcpStream, init: SOCKS5Init) -> Result<(), MyError> {
    Ok(())
}

async fn handle_socks4(stream: TcpStream, init: SOCKS4Init) -> Result<(), MyError> {
    Ok(())
}

async fn handle_connection(stream: TcpStream) -> Result<(), MyError> {
    let mut reader = IoBufReader::new(stream.compat());

    match timeout(Duration::from_secs(5), reader.parse(socks_init)).await?? {
        SOCKSInit::V4(init) => handle_socks4(reader.into_inner().into_inner(), init).await,
        SOCKSInit::V5(init) => handle_socks5(reader.into_inner().into_inner(), init).await,
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    handle_connection(stream).await;
                });
            }
            Err(e) => {
                println!("couldn't connect {}", e);
            }
        }
    }
}
