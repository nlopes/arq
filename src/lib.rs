//! Arq provides a way to interact with the Arq Backup data format as described in their
//! [arq_data_format.txt](https://www.arqbackup.com/arq_data_format.txt).
//!
//!
//!
extern crate aesni;
extern crate block_modes;
extern crate block_padding;
extern crate byteorder;
extern crate chrono;
#[cfg_attr(test, macro_use)]
extern crate hex_literal;
extern crate hmac;
extern crate lz4_sys;
extern crate plist;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha1;
extern crate sha2;

mod blob;
pub mod computer;
pub mod error;
pub mod folder;
pub mod object_encryption;
pub mod packset;
pub mod tree;
pub mod type_utils;

mod lz4;
mod utils;
