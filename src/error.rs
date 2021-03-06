pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    CryptoError,
    CipherError,
    BlockModeError,
    ParseError,
    ConversionError(std::str::Utf8Error),
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::ConversionError(ref err) => write!(f, "{}", err),
            _ => write!(f, "{}", self),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::ConversionError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl std::convert::From<hmac::crypto_mac::InvalidKeyLength> for Error {
    fn from(_error: hmac::crypto_mac::InvalidKeyLength) -> Error {
        Error::CryptoError
    }
}

impl std::convert::From<aesni::cipher::block::InvalidKeyLength> for Error {
    fn from(_error: aesni::cipher::block::InvalidKeyLength) -> Error {
        Error::CipherError
    }
}

impl std::convert::From<block_modes::BlockModeError> for Error {
    fn from(_error: block_modes::BlockModeError) -> Error {
        Error::BlockModeError
    }
}

impl std::convert::From<block_modes::InvalidKeyIvLength> for Error {
    fn from(_error: block_modes::InvalidKeyIvLength) -> Error {
        Error::BlockModeError
    }
}

impl std::convert::From<plist::Error> for Error {
    fn from(_error: plist::Error) -> Error {
        Error::ParseError
    }
}

impl std::convert::From<std::str::Utf8Error> for Error {
    fn from(error: std::str::Utf8Error) -> Error {
        Error::ConversionError(error)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl std::convert::From<std::num::ParseIntError> for Error {
    fn from(_error: std::num::ParseIntError) -> Error {
        Error::ParseError
    }
}
