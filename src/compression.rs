use crate::error::Result;
use crate::lz4;
use crate::type_utils::ArqRead;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum CompressionType {
    None,
    Gzip,
    LZ4,
}

impl CompressionType {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<CompressionType> {
        let c = reader.read_arq_i32()?;

        Ok(match c {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", c),
        })
    }

    pub fn decompress(compressed: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        Ok(match compression_type {
            CompressionType::LZ4 => lz4::decompress(compressed)?,
            CompressionType::Gzip => unimplemented!(),
            CompressionType::None => compressed.to_owned(),
        })
    }
}
