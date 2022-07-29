use nom::error::ErrorKind;
use thiserror::Error;
use tokio::time::error::Elapsed;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("IOError")]
    IO,
    #[error("ParseError")]
    Parse,
    #[error("TimeoutError")]
    Timeout,
    // #[error("NetworkError")]
    // Network,
    #[error("UnknownError")]
    Unknown,
}

impl From<std::io::Error> for MyError {
    fn from(_: std::io::Error) -> Self {
        MyError::IO
    }
}

impl From<Elapsed> for MyError {
    fn from(_: Elapsed) -> Self {
        MyError::Timeout
    }
}

impl<E> From<nom::error::Error<E>> for MyError {
    fn from(_: nom::error::Error<E>) -> Self {
        MyError::Parse
    }
}

impl<E> From<nom_bufreader::Error<E>> for MyError {
    fn from(e: nom_bufreader::Error<E>) -> Self {
        match e {
            nom_bufreader::Error::Io(_) => MyError::IO,
            _ => MyError::Unknown,
        }
    }
}

impl<E> nom::error::ParseError<E> for MyError {
    fn from_error_kind(_: E, _: ErrorKind) -> Self {
        MyError::Parse
    }

    fn append(_: E, _: ErrorKind, _: Self) -> Self {
        MyError::Parse
    }
}
