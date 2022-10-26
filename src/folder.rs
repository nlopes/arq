use std;
use std::collections::BTreeMap;
use std::io::{BufRead, Cursor, Seek};

use plist;

use crate::error::Result;
use crate::object_encryption;
use crate::type_utils::ArqRead;

/// FolderData contains metadata information written every time a new Commit is created.
///
/// It's a plist containing the previous and current Commit SHA1s, the SHA1 of the pack
/// file containing the new Commit, and whether the new Commit is a "rewrite" (because the
/// user deleted a backup record for instance).
#[derive(Deserialize, Default)]
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
    pub fn new<R: BufRead + Seek>(reader: R, sha1sum: &[u8]) -> Result<Self> {
        let fd: FolderData = plist::from_reader(reader)?;

        if sha1sum.len() > 40 {
            // 89 is "Y"
            assert_eq!(sha1sum[sha1sum.len() - 1], 89);
            assert_eq!(
                // subtracting 1 due to the Y appended to the sha.
                std::str::from_utf8(&sha1sum[..sha1sum.len() - 1])?,
                fd.new_head_sha1
            );
        }

        Ok(fd)
    }
}

/// Folder
///
///
/// Each time you add a folder for backup, Arq creates a UUID for it and stores 2
/// objects at the target:
///
/// `object: /<computer_uuid>/buckets/<folder_uuid>`
///
/// This file contains a "plist"-format XML document containing:
///   1. the 9-byte header "encrypted"
///   2. an EncryptedObject containing a plist like this:
///
/// ```ascii
///         <plist version="1.0">
///             <dict>
///                 <key>AWSRegionName</key>
///                 <string>us-east-1</string>
///                 <key>BucketUUID</key>
///                 <string>408E376B-ECF7-4688-902A-1E7671BC5B9A</string>
///                 <key>BucketName</key>
///                 <string>company</string>
///                 <key>ComputerUUID</key>
///                 <string>600150F6-70BB-47C6-A538-6F3A2258D524</string>
///                 <key>LocalPath</key>
///                 <string>/Users/stefan/src/company</string>
///                 <key>LocalMountPoint</key>
///                 </string>/</string>
///                 <key>StorageType</key>
///                 <integer>1</integer>
///                 <key>VaultName</key>
///                 <string>arq_408E376B-ECF7-4688-902A-1E7671BC5B9A</string>
///                 <key>VaultCreatedTime</key>
///                 <real>12345678.0</real>
///                 <key>Excludes</key>
///                 <dict>
///                     <key>Enabled</key>
///                     <false></false>
///                     <key>MatchAny</key>
///                     <true></true>
///                     <key>Conditions</key>
///                     <array></array>
///                 </dict>
///             </dict>
///         </plist>
/// ```
///
/// Only Glacier-backed folders have "VaultName" and "VaultCreatedTime" keys.
///
/// NOTE: The folder's UUID and name are called "BucketUUID" and "BucketName" in the
/// plist; this is a holdover from previous iterations of Arq and is not to be confused
/// with S3's "bucket" concept.
///
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
        Ok(plist::from_reader(Cursor::new(content))?)
    }

    pub fn new<R: BufRead + Seek>(mut reader: R, master_keys: &[Vec<u8>]) -> Result<Self> {
        let header = reader.read_bytes(9)?;
        assert_eq!(header, [101, 110, 99, 114, 121, 112, 116, 101, 100]); // 'encrypted'

        let obj = object_encryption::EncryptedObject::new(&mut reader)?;
        obj.validate(&master_keys[1])?;
        Folder::from_content(&obj.decrypt(&master_keys[0])?)
    }
}
