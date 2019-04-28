use chrono::prelude::{NaiveDateTime, DateTime, Utc};

use crate::error::Result;
use crate::type_utils::ArqRead;

pub struct Date {
    pub milliseconds_since_epoch: u64,
}

impl Date {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<Date> {
        let present = reader.read_bytes(1)?;
        let milliseconds_since_epoch = if present[0] == 0x01 {
            reader.read_arq_u64()?
        } else {
            0
        };

        Ok(Date {
            milliseconds_since_epoch,
        })
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Date is in milliseconds elapsed since epoch
        let naive_datetime =
            NaiveDateTime::from_timestamp((self.milliseconds_since_epoch / 1000) as i64, 0);
        let datetime_again: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
        write!(f, "{}", datetime_again)
    }
}
