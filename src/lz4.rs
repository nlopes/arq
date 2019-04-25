use byteorder::{NetworkEndian, WriteBytesExt};
use lz4_sys;
use std::io::Cursor;

use crate::error::Result;
use crate::type_utils::ArqRead;

pub fn lz4_compress(src: &[u8]) -> Result<Vec<u8>> {
    let src_ptr = src.as_ptr() as *const i8;
    let src_len = src.len() as i32;
    let original_len: i32;

    unsafe {
        original_len = lz4_sys::LZ4_compressBound(src_len);
    }

    let mut original_len_vec = vec![];
    original_len_vec.write_i32::<NetworkEndian>(original_len)?;

    let mut dst: Box<[i8]> = vec![0; original_len as usize + 4].into_boxed_slice();

    original_len_vec
        .iter()
        .enumerate()
        .for_each(|(i, n)| dst[i] = *n as i8);

    unsafe {
        let _c =
            lz4_sys::LZ4_compress_default(src_ptr, dst[4..].as_mut_ptr(), src_len, original_len);
        assert_ne!(_c, 0);
    }

    Ok(dst.into_vec().iter().map(|x| *x as u8).collect())
}

pub fn lz4_decompress(src: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(src);
    let original_len = reader.read_arq_i32()?;
    let src_ptr = src[4..].as_ptr() as *const i8;
    let src_len = src.len() as i32;
    let mut dst: Box<[i8]> = vec![0; original_len as usize].into_boxed_slice();

    unsafe {
        lz4_sys::LZ4_decompress_safe(src_ptr, dst.as_mut_ptr(), src_len - 4, original_len);
    }
    Ok(dst.into_vec().iter().map(|x| *x as u8).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4() {
        let test = String::from("Test string we want to compress").into_bytes();
        let decompressed = lz4_decompress(&lz4_compress(&test).unwrap()).unwrap();
        // We only read up to test.len() because decompressed fills the rest of the buffer
        // with zeros
        assert_eq!(test[..], decompressed[..test.len()]);
    }
}
