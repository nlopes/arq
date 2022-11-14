use std::convert::TryInto;
use std::io::Cursor;

use crate::error::Result;
use crate::type_utils::ArqRead;

#[cfg(test)]
fn compress(src: &[u8]) -> Result<Vec<u8>> {
    let length: [u8; 4] = (src.len() as i32).to_be_bytes();
    let compressed_data = lz4_flex::compress(src);
    let all = [&length[..], &compressed_data].concat();
    Ok(all)
}

pub fn decompress(src: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(src);
    let original_len = reader.read_arq_i32()?;
    Ok(lz4_flex::decompress(&src[4..], original_len.try_into()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4() {
        let test = String::from("Test string we want to compress").into_bytes();
        let compressed = compress(&test).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        // We only read up to test.len() because decompressed fills the rest of the buffer
        // with zeros
        assert_eq!(test[..], decompressed[..test.len()]);
    }
}
