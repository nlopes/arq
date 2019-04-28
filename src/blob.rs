use crate::date::Date;
use crate::error::Result;
use crate::type_utils::ArqRead;

/// BlobKey
///
/// BlobKeys are used as an auxiliary data structure and there is *probably* no need to
/// interact with this directly unless you're working within this library.
pub struct BlobKey {
    pub sha1: String,
    pub is_encryption_key_stretched: bool, /* only present for Tree version 14 or later, Commit version 4 or later */
    pub storage_type: u32, /* 1==S3, 2==Glacier; only present for Tree version 17 or later */

    /* only present for Tree version 17 or later */
    pub archive_id: String,
    pub archive_size: u64,
    pub archive_upload_date: Date,
}

impl BlobKey {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<Option<BlobKey>> {
        let sha1 = reader.read_arq_string()?;
        let is_encryption_key_stretched = reader.read_arq_bool()?;
        let storage_type = reader.read_arq_u32()?;
        let archive_id = reader.read_arq_string()?;
        let archive_size = reader.read_arq_u64()?;
        let archive_upload_date = reader.read_arq_date()?;

        if sha1.is_empty() {
            return Ok(None);
        }

        Ok(Some(BlobKey {
            sha1,
            is_encryption_key_stretched,
            storage_type,
            archive_id,
            archive_size,
            archive_upload_date,
        }))
    }
}
