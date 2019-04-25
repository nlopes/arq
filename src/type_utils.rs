use byteorder::{NetworkEndian, ReadBytesExt};
use chrono::prelude::*;
use std;
use std::io::Read;

use crate::error::Result;

pub trait ArqRead {
    fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>>;
    fn read_arq_string(&mut self) -> Result<String>;
    fn read_arq_bool(&mut self) -> Result<bool>;
    fn read_arq_u32(&mut self) -> Result<u32>;
    fn read_arq_i32(&mut self) -> Result<i32>;
    fn read_arq_u64(&mut self) -> Result<u64>;
    fn read_arq_i64(&mut self) -> Result<i64>;
    fn read_arq_compression_type(&mut self) -> Result<ArqCompressionType>;
    fn read_arq_data(&mut self) -> Result<Vec<u8>>;
    fn read_arq_date(&mut self) -> Result<ArqDate>;
}

impl<T: Read> ArqRead for T
where
    T: Read,
{
    fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0; count];
        self.read_exact(&mut buffer[..])?;
        Ok(buffer)
    }

    fn read_arq_string(&mut self) -> Result<String> {
        let present = self.read_bytes(1)?;

        Ok(if present[0] == 0x01 {
            let strlen = self.read_u64::<NetworkEndian>()?;
            let data_bytes = self.read_bytes(strlen as usize)?;
            std::str::from_utf8(&data_bytes)?.to_string()
        } else {
            String::new()
        })
    }

    fn read_arq_bool(&mut self) -> Result<bool> {
        let flag = self.read_bytes(1)?;
        Ok(flag[0] == 0x01)
    }

    fn read_arq_u32(&mut self) -> Result<u32> {
        Ok(self.read_u32::<NetworkEndian>()?)
    }

    fn read_arq_i32(&mut self) -> Result<i32> {
        Ok(self.read_i32::<NetworkEndian>()?)
    }

    fn read_arq_u64(&mut self) -> Result<u64> {
        Ok(self.read_u64::<NetworkEndian>()?)
    }

    fn read_arq_i64(&mut self) -> Result<i64> {
        Ok(self.read_i64::<NetworkEndian>()?)
    }

    fn read_arq_compression_type(&mut self) -> Result<ArqCompressionType> {
        ArqCompressionType::new(self)
    }

    fn read_arq_date(&mut self) -> Result<ArqDate> {
        ArqDate::new(self)
    }

    fn read_arq_data(&mut self) -> Result<Vec<u8>> {
        let strlen = self.read_u64::<NetworkEndian>()?;
        let data_bytes = self.read_bytes(strlen as usize)?;
        Ok(data_bytes.to_vec())
    }
}

#[derive(PartialEq, Debug)]
pub enum ArqCompressionType {
    None,
    Gzip,
    LZ4,
}

impl ArqCompressionType {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<ArqCompressionType> {
        let c = reader.read_arq_i32()?;

        Ok(match c {
            0 => ArqCompressionType::None,
            1 => ArqCompressionType::Gzip,
            2 => ArqCompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", c),
        })
    }
}

pub struct ArqDate {
    milliseconds_since_epoch: u64,
}

impl ArqDate {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<ArqDate> {
        let present = reader.read_bytes(1)?;
        let milliseconds_since_epoch = if present[0] == 0x01 {
            reader.read_arq_u64()?
        } else {
            0
        };

        Ok(ArqDate {
            milliseconds_since_epoch,
        })
    }
}

impl std::fmt::Display for ArqDate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Date is in milliseconds elapsed since epoch
        let naive_datetime =
            NaiveDateTime::from_timestamp((self.milliseconds_since_epoch / 1000) as i64, 0);
        let datetime_again: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
        write!(f, "{}", datetime_again)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_bytes() {
        let empty: Vec<u8> = vec![];

        let data = [12, 34, 11, 56, 78, 92];
        let mut reader = Cursor::new(data);

        assert_eq!(vec![12, 34], reader.read_bytes(2).unwrap());
        assert_eq!(vec![11, 56, 78, 92], reader.read_bytes(4).unwrap());
        assert_eq!(empty, reader.read_bytes(0).unwrap());
    }

    #[test]
    fn test_read_arq_u32() {
        let mut reader = Cursor::new(vec![0, 0, 0, 2, 255, 255, 255, 255]);
        let mut n = reader.read_arq_u32().unwrap();
        assert_eq!(n, 2);
        n = reader.read_arq_u32().unwrap();
        assert_eq!(n, std::u32::MAX);
    }

    #[test]
    fn test_read_arq_i32() {
        let mut reader = Cursor::new(vec![0, 0, 0, 2, 254, 255, 255, 255]);
        let mut n = reader.read_arq_i32().unwrap();
        assert_eq!(n, 2);
        n = reader.read_arq_i32().unwrap();
        assert_eq!(n, -16777217);
    }

    #[test]
    fn test_read_arq_u64() {
        let mut reader = Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 254, 255, 255, 255]);
        let mut n = reader.read_arq_u64().unwrap();
        assert_eq!(n, 2);
        n = reader.read_arq_u64().unwrap();
        assert_eq!(n, 4278190079);
    }

    #[test]
    fn test_read_arq_i64() {
        let mut reader = Cursor::new(vec![
            0, 0, 0, 0, 0, 0, 0, 2, 254, 255, 255, 255, 255, 255, 255, 255, 127, 255, 255, 255,
            255, 255, 255, 255,
        ]);
        let mut n = reader.read_arq_i64().unwrap();
        assert_eq!(n, 2);

        n = reader.read_arq_i64().unwrap();
        assert_eq!(n, -72057594037927937);

        n = reader.read_arq_i64().unwrap();
        assert_eq!(n, std::i64::MAX);
    }

    #[test]
    fn test_arq_compression_type() {
        let mut ct_none_reader = Cursor::new(vec![0, 0, 0, 0]);
        let mut ct = ct_none_reader.read_arq_compression_type().unwrap();
        assert_eq!(ct, ArqCompressionType::None);

        let mut ct_gzip_reader = Cursor::new(vec![0, 0, 0, 1]);
        ct = ct_gzip_reader.read_arq_compression_type().unwrap();
        assert_eq!(ct, ArqCompressionType::Gzip);

        let mut ct_lz4_reader = Cursor::new(vec![0, 0, 0, 2]);
        ct = ct_lz4_reader.read_arq_compression_type().unwrap();
        assert_eq!(ct, ArqCompressionType::LZ4);
    }

    #[test]
    fn test_read_arq_bool() {
        let mut reader = Cursor::new(vec![0, 1]); // [false, true]

        let mut ct = reader.read_arq_bool().unwrap();
        assert!(!ct);
        ct = reader.read_arq_bool().unwrap();
        assert!(ct);
    }

    #[test]
    fn test_read_arq_string() {
        let mut reader_without_string = Cursor::new(vec![0]);
        let mut ct = reader_without_string.read_arq_string().unwrap();
        assert_eq!(ct, "");

        // Read four letter string: AHBH
        let mut reader_with_string = Cursor::new(vec![1, 0, 0, 0, 0, 0, 0, 0, 4, 65, 72, 66, 72]);
        ct = reader_with_string.read_arq_string().unwrap();
        assert_eq!(ct, "AHBH");
    }

    #[test]
    fn test_read_arq_data() {
        let empty: Vec<u8> = vec![];

        let mut reader_without_data = Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let mut ct = reader_without_data.read_arq_data().unwrap();
        assert_eq!(ct.len(), 0);
        assert_eq!(ct, empty);

        let mut reader_with_data = Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]);
        ct = reader_with_data.read_arq_data().unwrap();
        assert_eq!(ct.len(), 3);
        assert_eq!(ct, vec![1, 2, 3]);
    }

    #[test]
    fn test_read_arq_date() {
        let mut reader_without_date = Cursor::new(vec![0]);
        let mut ct = reader_without_date.read_arq_date().unwrap();
        assert_eq!(ct.milliseconds_since_epoch, 0);

        let mut reader_with_date = Cursor::new(vec![1, 0, 0, 0, 127, 167, 127, 83, 0]);
        ct = reader_with_date.read_arq_date().unwrap();
        assert_eq!(format!("{}", ct), "1987-05-17 17:29:45 UTC");
    }
}
