mod error;
mod parse;
mod socks;

use futures_util::io::BufReader as IoBufReader;

use std::time::Duration;

use crate::error::MyError;
use crate::parse::socks_init;
use crate::socks::{SOCKS4Cmd, SOCKS4Init, SOCKS5Init, SOCKSInit};
use nom_bufreader::AsyncParse;
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;

async fn run_connection(mut client: TcpStream, mut server: TcpStream) {
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();

    let client_to_server = async {
        copy(&mut cr, &mut sw).await?;
        sw.shutdown().await
    };

    let server_to_client = async {
        copy(&mut sr, &mut cw).await?;
        cw.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client);
}

async fn handle_socks5(mut stream: TcpStream, init: SOCKS5Init) -> Result<(), MyError> {
    Ok(())
}

async fn handle_socks4(mut stream: TcpStream, init: SOCKS4Init) -> Result<(), MyError> {
    match init.cmd {
        SOCKS4Cmd::Connect => {
            let mut msg: [u8; 8] = [0; 8];

            // apparently timeout is 2 mins for connection establishment
            match timeout(
                Duration::from_secs(120),
                TcpStream::connect(String::from(init.dest)),
            )
            .await?
            {
                Ok(forward) => {
                    // connection accepted
                    msg[1] = 0x5a;
                    stream.write(msg.as_slice()).await?;

                    run_connection(stream, forward).await;

                    Ok(())
                }
                Err(e) => {
                    // connection failed
                    // send rejection msg
                    msg[1] = 0x5b;
                    stream.write(msg.as_slice()).await?;
                    Err(MyError::from(e))
                }
            }
        }
        SOCKS4Cmd::Bind => {
            unimplemented!();
        }
    }
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
