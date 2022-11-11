//! Packs
//! -----
//!
//! Each folder configured for backup maintains 2 "packsets", one for trees and commits,
//! and one for all other small files. The packsets are named:
//!
//! ```ascii
//! <folder_uuid>-trees
//! <folder_uuid>-blobs
//! ```
//!
//! Small files are separated into 2 packsets because the trees and commits are cached
//! locally (so that Arq gives reasonable performance for browsing backups); all other
//! small blobs don't need to be cached.
//!
//! A packset is a set of "packs". When Arq is backing up a folder, it combines small
//! files into a single larger packfile; when the packfile reaches 10MB, it is stored at
//! the destination. Also, when Arq finishes backing up a folder it stores its unsaved
//! packfiles no matter their sizes.
//!
//! When storing a pack, Arq stores the packfile as:
//!
//! `/<computer_uuid>/packsets/<folder_uuid>-(blobs|trees)/<sha1>.pack`
//!
//! It also stores an index of the SHA1s contained in the pack as:
//!
//! `/<computer_uuid>/packsets/<folder_uuid>-(blobs|trees)/<sha1>.index`
use byteorder::{NetworkEndian, ReadBytesExt};
use std;
use std::io::{BufRead, Cursor, Seek, SeekFrom};

use crate::compression::CompressionType;
use crate::error::Result;
use crate::object_encryption::{calculate_sha1sum, EncryptedObject};
use crate::type_utils::ArqRead;
use crate::utils::convert_to_hex_string;

///Pack File Format
///----------------
///
///```ascii
///signature                   50 41 43 4b ("PACK")
///version (2)                 00 00 00 02 (network-byte-order 4 bytes)
///object count                00 00 00 00 (network-byte-order 8 bytes)
///object count                00 00 f0 f2
///object[0] mimetype not null 01          (1 byte) (this is usually zero)
///object[0] mimetype strlen   00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                            00 00 00 08
///object[0] mimetype string   xx xx xx xx (n bytes)
///                            xx xx xx xx
///object[0] name not null     01          (1 byte) (this is usually zero)
///object[0] name strlen       00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                            00 00 00 08
///object[0] name string       xx xx xx xx (n bytes)
///                            xx xx xx xx
///object[0] data length       00 00 00 00 (network-byte-order 8 bytes)
///                            00 00 00 06
///object[0] data              xx xx xx xx (n bytes)
///                            xx xx
///...
///object[f0f2] mimetype not null 01       (1 byte) (this is usually zero)
///object[f0f2] mimetype len   00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                            00 00 00 08
///object[f0f2] mimetype str   xx xx xx xx (n bytes)
///                            xx xx xx xx
///object[f0f2] name not null  01          (1 byte) (this is usually zero)
///object[f0f2] name strlen    00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                            00 00 00 08
///object[f0f2] name string    xx xx xx xx (n bytes)
///                            xx xx xx xx
///object[f0f2] data length    00 00 00 00 (network-byte-order 8 bytes)
///                            00 00 00 04
///object[f0f2] data           12 34 12 34
///20-byte SHA1 of all of the  xx xx xx xx
///above                       xx xx xx xx
///                            xx xx xx xx
///                            xx xx xx xx
///                            xx xx xx xx
///```
pub struct Pack {
    pub version: Vec<u8>,
    pub objects: Vec<PackObject>,
}

/// PackObject
/// ----------
///
/// This is an auxiliary structure to access the objects described in the "Pack File
/// Format". Each one of these has the following format:
///
/// ```ascii
/// mimetype not null 01          (1 byte) (this is usually zero)
/// mimetype strlen   00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                   00 00 00 08
/// mimetype string   xx xx xx xx (n bytes)
///                   xx xx xx xx
/// name not null     01          (1 byte) (this is usually zero)
/// name strlen       00 00 00 00 (network-byte-order 8 bytes) (this isn't here if not-null is zero)
///                   00 00 00 08
/// name string       xx xx xx xx (n bytes)
///                   xx xx xx xx
/// data length       00 00 00 00 (network-byte-order 8 bytes)
///                   00 00 00 06
/// data              xx xx xx xx (n bytes)
///                   xx xx
///```
pub struct PackObject {
    pub mimetype: String,
    pub name: String,
    pub data: EncryptedObject,
}

/// Pack Index Format
/// -----------------
///
/// ```ascii
/// magic number                ff 74 4f 63
/// version (2)                 00 00 00 02 network-byte-order
/// fanout[0]                   00 00 00 02 (4-byte count of SHA1s starting with 0x00)
/// ...
/// fanout[255]                 00 00 f0 f2 (4-byte count of total objects == count of SHA1s starting with 0xff or smaller)
/// object[0]                   00 00 00 00 (8-byte network-byte-order offset)
///                             00 00 00 00
///                             00 00 00 00 (8-byte network-byte-order data length)
///                             00 00 00 00
///                             00 xx xx xx (sha1 starting with 00)
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             00 00 00 00 (4 bytes for alignment)
/// object[1]                   00 00 00 00 (8-byte network-byte-order offset)
///                             00 00 00 00
///                             00 00 00 00 (8-byte network-byte-order data length)
///                             00 00 00 00
///                             00 xx xx xx (sha1 starting with 00)
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             00 00 00 00 (4 bytes for alignment)
/// object[2]                   00 00 00 00 (8-byte network-byte-order offset)
///                             00 00 00 00
///                             00 00 00 00 (8-byte network-byte-order data length)
///                             00 00 00 00
///                             00 xx xx xx (sha1 starting with 00)
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             00 00 00 00 (4 bytes for alignment)
/// ...
/// object[f0f1]                00 00 00 00 (8-byte network-byte-order offset)
///                             00 00 00 00
///                             00 00 00 00 (8-byte network-byte-order data length)
///                             00 00 00 00
///                             ff xx xx xx (sha1 starting with ff)
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             00 00 00 00 (4 bytes for alignment)
/// Glacier archiveId not null  01          (1 byte)                                    /* Glacier only */
/// Glacier archiveId strlen    00 00 00 00 (network-byte-order 8 bytes)                /* Glacier only */
///                             00 00 00 08                                             /* Glacier only */
/// Glacier archiveId string    xx xx xx xx (n bytes)                                   /* Glacier only */
///                             xx xx xx xx                                             /* Glacier only */
/// Glacier pack size           00 00 00 00 (8-byte network-byte-order data length)     /* Glacier only */
///                             00 00 00 00                                             /* Glacier only */
/// 20-byte SHA1 of all of the  xx xx xx xx
/// above                       xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
/// ```
pub struct PackIndex {
    pub version: Vec<u8>,
    pub fanout: Vec<Vec<u8>>,
    pub objects: Vec<PackIndexObject>,

    pub glacier_archive_id_present: bool,
    // TODO(nlopes): maybe this should be String
    pub glacier_archive_id: Vec<u8>,
    pub glacier_pack_size: usize,
}

/// PackIndexObject
/// ----------
///
/// This is an auxiliary structure to access the objects described in the "Pack Index
/// Format". Each one of these has the following format:
///
/// ```ascii
/// offset       00 00 00 00 (8-byte network-byte-order offset)
///              00 00 00 00
/// data length  00 00 00 00 (8-byte network-byte-order data length)
///              00 00 00 00
/// sha1         00 xx xx xx (sha1 starting with 00)
///              xx xx xx xx
///              xx xx xx xx
///              xx xx xx xx
///              xx xx xx xx
/// alignment    00 00 00 00 (4 bytes for alignment) - we don't include this one
/// ```
pub struct PackIndexObject {
    pub offset: usize,
    pub data_len: usize,
    pub sha1: String,
}

impl PackIndex {
    pub fn new<R: BufRead + ArqRead + Seek>(mut reader: R) -> Result<PackIndex> {
        let magic_number = reader.read_bytes(4)?;
        assert_eq!(magic_number, [255, 116, 79, 99]); // ff 74 4f 63

        let version = reader.read_bytes(4)?;

        let mut fanout = Vec::new();
        while fanout.len() < 256 {
            fanout.push(reader.read_bytes(4)?.to_vec());
        }

        // The object count is in the last fanout entry
        let count_vec = &fanout[255].clone();
        let mut rdr = Cursor::new(count_vec);
        let mut object_count = rdr.read_u32::<NetworkEndian>()? as usize;

        let mut objects = Vec::new();
        while object_count > 0 {
            objects.push(PackIndexObject::new(&mut reader)?);
            object_count -= 1;
        }

        let mut glacier_archive_id_present: bool = false;
        let mut glacier_archive_id: Vec<u8> = Vec::new();
        let mut glacier_pack_size = 0;

        // TODO(nlopes): This is ugly. I don't have a current position due to using a
        // "cursor"/reader. So what I do is I try to read 21 bytes. If I can, then I know
        // I have more than just the sha1 of the content. If I can't, then I'm back where
        // I was and I do nothing.
        let mut _buf = vec![0; 21];
        if reader.read_exact(&mut _buf).is_ok() {
            // This is a easier condition than trying to read the bytes for glacier.  If all
            // the bytes read + 20 (for the final sha1) account for the entire length of the
            // content, we're at the end of data and don't need to read anything related to
            // glacier.
            let glacier_archive_id_flag = reader.read_bytes(1)?;

            if glacier_archive_id_flag[0] == 0x01 {
                glacier_archive_id_present = true;
                let glacier_archive_id_strlen = reader.read_u64::<NetworkEndian>()?;
                glacier_archive_id = reader
                    .read_bytes(glacier_archive_id_strlen as usize)?
                    .to_vec();
                glacier_pack_size = reader.read_u64::<NetworkEndian>()?;
            }
        }

        let sha1_checksum_start = reader.seek(SeekFrom::End(0))? - 20;
        let mut content = vec![0; sha1_checksum_start as usize];

        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut content)?;

        let sha1 = reader.read_bytes(20)?;
        assert_eq!(calculate_sha1sum(&content), sha1);

        Ok(PackIndex {
            version: version.to_vec(),
            fanout,
            objects,
            glacier_archive_id_present,
            glacier_archive_id,
            glacier_pack_size: glacier_pack_size as usize,
        })
    }
}

impl Pack {
    pub fn new<R: ArqRead + BufRead + Seek>(mut reader: R) -> Result<Pack> {
        let signature = reader.read_bytes(4)?;
        assert_eq!(signature, [80, 65, 67, 75]);
        let version = reader.read_bytes(4)?;
        let mut object_count = reader.read_u64::<NetworkEndian>()? as usize;
        let mut objects: Vec<PackObject> = Vec::new();
        while object_count > 0 {
            objects.push(PackObject::new(&mut reader)?);
            object_count -= 1;
        }

        let sha1_checksum_start = reader.seek(SeekFrom::End(0))? - 20;
        let mut content = vec![0; sha1_checksum_start as usize];

        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut content)?;

        let sha1 = reader.read_bytes(20)?;
        assert_eq!(calculate_sha1sum(&content), sha1);

        Ok(Pack {
            version: version.to_vec(),
            objects,
        })
    }
}

impl PackIndexObject {
    pub fn new<R: ArqRead + BufRead + Seek>(mut reader: R) -> Result<Self> {
        let offset = reader.read_u64::<NetworkEndian>()?;
        let data_len = reader.read_u64::<NetworkEndian>()?;
        let sha1 = reader.read_bytes(20)?;
        let _padding = reader.read_bytes(4)?;

        Ok(PackIndexObject {
            offset: offset as usize,
            data_len: data_len as usize,
            sha1: convert_to_hex_string(&sha1),
        })
    }
}

impl PackObject {
    pub fn new<R: ArqRead + BufRead + Seek>(mut reader: R) -> Result<PackObject> {
        // If mimetype present
        let mimetype = if reader.read_arq_bool()? {
            reader.read_arq_string()?
        } else {
            String::new()
        };

        // If name present
        let name = if reader.read_arq_bool()? {
            reader.read_arq_string()?
        } else {
            String::new()
        };

        let data = reader.read_arq_data()?;
        let mut data_reader = Cursor::new(data);

        Ok(PackObject {
            mimetype,
            name,
            data: EncryptedObject::new(&mut data_reader)?,
        })
    }

    pub fn original(
        &self,
        compression_type: CompressionType,
        master_key: &[u8],
    ) -> Result<Vec<u8>> {
        let decrypted = self.data.decrypt(master_key)?;
        let content = CompressionType::decompress(&decrypted, compression_type)?;
        Ok(content)
    }
}
