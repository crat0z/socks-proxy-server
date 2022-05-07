mod parse;
mod socks;

use futures_util::io::BufReader as IoBufReader;
use std::time::Duration;

use crate::parse::socks_init;
use nom_bufreader::async_bufreader::BufReader;
use nom_bufreader::AsyncParse;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    let mut i = BufReader::new(IoBufReader::new(
        listener.accept().await.unwrap().0.compat(),
    ));

    let msg = timeout(Duration::from_secs(5), i.parse(socks_init))
        .await
        .unwrap();
}
