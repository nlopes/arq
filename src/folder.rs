use std;
use std::collections::BTreeMap;
use std::io::{BufRead, Cursor, Seek};

use plist::serde::deserialize;

use crate::error::Result;
use crate::object_encryption;
use crate::type_utils::ArqRead;

/// FolderData contains metadata information written every time a new Commit is created.
///
/// It's a plist containing the previous and current Commit SHA1s, the SHA1 of the pack
/// file containing the new Commit, and whether the new Commit is a "rewrite" (because the
/// user deleted a backup record for instance).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct FolderData {
    #[serde(rename = "oldHeadSHA1")]
    pub old_head_sha1: String,
    pub old_head_stretch_key: bool,
    #[serde(rename = "newHeadSHA1")]
    pub new_head_sha1: String,
    pub new_head_stretch_key: bool,
    pub is_rewrite: bool,
    #[serde(rename = "packSHA1")]
    pub pack_sha1: String,
}

impl FolderData {
    pub fn from_reader<R: BufRead + Seek>(reader: R, sha1sum: &[u8]) -> Result<Self> {
        let fd: FolderData = deserialize(reader)?;

        if sha1sum.len() > 40 {
            // 89 is "Y"
            assert_eq!(sha1sum[sha1sum.len()-1], 89);
            assert_eq!(
                // subtracting 1 due to the Y appended to the sha.
                std::str::from_utf8(&sha1sum[..sha1sum.len() - 1])?,
                fd.new_head_sha1
            );
        }

        Ok(fd)
    }
}

impl Default for FolderData {
    fn default() -> Self {
        FolderData {
            old_head_sha1: String::new(),
            old_head_stretch_key: false,
            new_head_sha1: String::new(),
            new_head_stretch_key: false,
            is_rewrite: false,
            pack_sha1: String::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Folder {
    pub bucket_name: String,
    #[serde(rename = "BucketUUID")]
    pub bucket_uuid: String,
    #[serde(rename = "ComputerUUID")]
    pub computer_uuid: String,
    pub endpoint: String,
    pub exclude_items_with_time_machine_exclude_metadata_flag: bool,
    pub excludes: BTreeMap<String, Vec<String>>, // TODO(nlopes): this one is provably wrong
    pub ignored_relative_paths: Vec<String>,
    pub local_mount_point: String,
    pub local_path: String,
    pub skip_during_backup: bool,
    pub skip_if_not_mounted: bool,
    pub storage_type: u8,
}

impl Folder {
    fn from_content(content: &[u8]) -> Result<Self> {
        Ok(deserialize(Cursor::new(content))?)
    }

    pub fn from_reader<R: BufRead + Seek>(mut reader: R, master_keys: &[Vec<u8>]) -> Result<Self> {
        let header = reader.read_bytes(9)?;
        assert_eq!(header, [101, 110, 99, 114, 121, 112, 116, 101, 100]); // 'encrypted'

        let obj = object_encryption::EncryptedObject::from_reader(&mut reader)?;
        obj.validate(&master_keys[1])?;
        Folder::from_content(&obj.decrypt(&master_keys[0])?)
    }
}
