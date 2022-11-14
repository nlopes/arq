//! Commits, Trees and Nodes
//! ------------------------
//!
//! When Arq backs up a folder, it creates 3 types of objects: "commits", "trees"
//! and "blobs".
//!
//! Each backup that you see in Arq corresponds to a "commit" object in the backup
//! data.  Its name is the SHA1 of its contents. The commit contains the SHA1 of a
//! "tree" object in the backup data. This tree corresponds to the folder you're
//! backing up.
//!
//! Each tree contains "nodes"; each node has either the SHA1 of another tree, or
//! the SHA1 of a file (or multiple SHA1s, see "Tree format" below).
//!
//! All commits, trees and blobs are stored as EncryptedObjects.
use std;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

use crate::blob;
use crate::compression::CompressionType;
use crate::date::Date;
use crate::error::Result;
use crate::type_utils::ArqRead;

/// Node
///
/// Each [Node] contains the following bytes:
///
/// ```ascii
///     [Bool:isTree]
///     [Bool:treeContainsMissingItems] /* present for Tree version >= 18 */
///     [Bool:data_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:data_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:xattrs_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:xattrs_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:acl_is_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:acl_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Int32:data_blob_keys_count]
///     (
///         [BlobKey:data_blob_key]
///     )   /* repeat <data_blob_keys_count> times */
///     [UIn64:data_size]
///     [String:"<thumbnail sha1>"] /* only present for Tree version 18 or earlier (never used) */
///     [Bool:is_thumbnail_encryption_key_stretched] /* only present for Tree version 14 to 18 */
///     [String:"<preview sha1>"] /* only present for Tree version 18 or earlier (never used) */
///     [Bool:is_preview_encryption_key_stretched] /* only present for Tree version 14 to 18 */
///     [BlobKey:xattrs_blob_key] /* null if file has no xattrs */
///     [UInt64:xattrs_size]
///     [BlobKey:acl_blob_key] /* null if file has no acl */
///     [Int32:uid]
///     [Int32:gid]
///     [Int32:mode]
///     [Int64:mtime_sec]
///     [Int64:mtime_nsec]
///     [Int64:flags]
///     [Int32:finderFlags]
///     [Int32:extendedFinderFlags]
///     [String:"<finder file type>"]
///     [String:"<finder file creator>"]
///     [Bool:is_file_extension_hidden]
///     [Int32:st_dev]
///     [Int32:st_ino]
///     [UInt32:st_nlink]
///     [Int32:st_rdev]
///     [Int64:ctime_sec]
///     [Int64:ctime_nsec]
///     [Int64:create_time_sec]
///     [Int64:create_time_nsec]
///     [Int64:st_blocks]
///     [UInt32:st_blksize]
/// ```
///
/// Notes:
///
/// - A Node can have multiple data SHA1s if the file is very large. Arq breaks up large
///   files into multiple blobs using a rolling checksum algorithm. This way Arq only
///   backs up the parts of a file that have changed.
///
/// - "<xattrs_blob_key>" is the key of a blob containing the sorted extended attributes
///   of the file (see "XAttrSet Format" below). Note this means extended-attribute sets
///   are "de-duplicated".
///
/// - "<acl_blob_key>" is the SHA1 of the blob containing the result of acl_to_text() on
/// the file's ACL. Note this means the ACLs are "de-duplicated".
///
/// - "create_time_sec" and "create_time_nsec" contain the value of the ATTR_CMN_CRTIME
/// attribute of the file
///
///
/// XAttrSet Format
/// ---------------
///
/// Each XAttrSet blob contains the following bytes:
///
/// ```ascii
///     58 41 74 74 72 53 65 74  56 30 30 32    "XAttrSetV002"
///     [UInt64:xattr_count]
///     (
///         [String:"<xattr name>"] /* can't be null */
///         [Data:xattr_data]
///     )
/// ```
pub struct Node {
    pub is_tree: bool,
    pub tree_contains_missing_items: bool,
    pub data_compression_type: CompressionType,
    pub xattrs_compression_type: CompressionType,
    pub acl_compression_type: CompressionType,
    pub data_blob_keys: Vec<blob::BlobKey>,
    pub data_size: u64,
    pub xattrs_blob_key: Option<blob::BlobKey>,
    pub xattrs_size: u64,
    pub acl_blob_key: Option<blob::BlobKey>,
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub finder_file_type: String,
    pub finder_file_creator: String,
    pub is_file_extension_hidden: bool,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
}

impl Node {
    pub fn new<R: ArqRead + BufRead>(mut reader: R) -> Result<Node> {
        let is_tree = reader.read_arq_bool()?;
        let tree_contains_missing_items = reader.read_arq_bool()?;
        let data_compression_type = reader.read_arq_compression_type()?;
        let xattrs_compression_type = reader.read_arq_compression_type()?;
        let acl_compression_type = reader.read_arq_compression_type()?;
        let mut data_blob_keys_count = reader.read_arq_i32()?;

        let mut data_blob_keys = Vec::new();
        while data_blob_keys_count > 0 {
            if let Some(data_blob_key) = blob::BlobKey::new(&mut reader)? {
                data_blob_keys.push(data_blob_key);
                data_blob_keys_count -= 1;
            }
        }
        let data_size = reader.read_arq_u64()?;
        let xattrs_blob_key = blob::BlobKey::new(&mut reader)?;
        let xattrs_size = reader.read_arq_u64()?;
        let acl_blob_key = blob::BlobKey::new(&mut reader)?;
        let uid = reader.read_arq_i32()?;
        let gid = reader.read_arq_i32()?;
        let mode = reader.read_arq_i32()?;
        let mtime_sec = reader.read_arq_i64()?;
        let mtime_nsec = reader.read_arq_i64()?;
        let flags = reader.read_arq_i64()?;
        let finder_flags = reader.read_arq_i32()?;
        let extended_finder_flags = reader.read_arq_i32()?;
        let finder_file_type = reader.read_arq_string()?;
        let finder_file_creator = reader.read_arq_string()?;
        let is_file_extension_hidden = reader.read_arq_bool()?;
        let st_dev = reader.read_arq_i32()?;
        let st_ino = reader.read_arq_i32()?;
        let st_nlink = reader.read_arq_u32()?;
        let st_rdev = reader.read_arq_i32()?;
        let ctime_sec = reader.read_arq_i64()?;
        let ctime_nsec = reader.read_arq_i64()?;
        let create_time_sec = reader.read_arq_i64()?;
        let create_time_nsec = reader.read_arq_i64()?;
        let st_blocks = reader.read_arq_i64()?;
        let st_blksize = reader.read_arq_u32()?;

        Ok(Node {
            is_tree,
            tree_contains_missing_items,
            data_compression_type,
            xattrs_compression_type,
            acl_compression_type,
            data_blob_keys,
            data_size,
            xattrs_blob_key,
            xattrs_size,
            acl_blob_key,
            uid,
            gid,
            mode,
            mtime_sec,
            mtime_nsec,
            flags,
            finder_flags,
            extended_finder_flags,
            finder_file_type,
            finder_file_creator,
            is_file_extension_hidden,
            st_dev,
            st_ino,
            st_nlink,
            st_rdev,
            ctime_sec,
            ctime_nsec,
            create_time_sec,
            create_time_nsec,
            st_blocks,
            st_blksize,
        })
    }
}

/// Tree
///
/// A tree contains the following bytes:
///
/// ```ascii
///     54 72 65 65 56 30 32 32             "TreeV022"
///     [Bool:xattrs_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:xattrs_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:acl_is_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:acl_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Int32:xattrs_compression_type] /* present for Tree version >= 20; older Trees are gzip compression type */
///     [Int32:acl_compression_type] /* present for Tree version >= 20; older Trees are gzip compression type */
///     [BlobKey:xattrs_blob_key] /* null if directory has no xattrs */
///     [UInt64:xattrs_size]
///     [BlobKey:acl_blob_key] /* null if directory has no acl */
///     [Int32:uid]
///     [Int32:gid]
///     [Int32:mode]
///     [Int64:mtime_sec]
///     [Int64:mtime_nsec]
///     [Int64:flags]
///     [Int32:finderFlags]
///     [Int32:extendedFinderFlags]
///     [Int32:st_dev]
///     [Int32:st_ino]
///     [UInt32:st_nlink]
///     [Int32:st_rdev]
///     [Int64:ctime_sec]
///     [Int64:ctime_nsec]
///     [Int64:st_blocks]
///     [UInt32:st_blksize]
///     [UInt64:aggregate_size_on_disk] /* only present for Tree version 11 to 16 (never used) */
///     [Int64:create_time_sec] /* only present for Tree version 15 or later */
///     [Int64:create_time_nsec] /* only present for Tree version 15 or later */
///     [UInt32:missing_node_count] /* only present for Tree version 18 or later */
///     (
///         [String:"<missing_node_name>"] /* only present for Tree version 18 or later */
///     )   /* repeat <missing_node_count> times */
///     [UInt32:node_count]
///     (
///         [String:"<file name>"] /* can't be null */
///         [Node]
///     )   /* repeat <node_count> times */
/// ```
pub struct Tree {
    pub version: u32,
    pub xattrs_compression_type: CompressionType,
    pub acl_compression_type: CompressionType,
    pub xattrs_blob_key: Option<blob::BlobKey>,
    pub xattrs_size: u64,
    pub acl_blob_key: Option<blob::BlobKey>,
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
    pub missing_nodes: Vec<String>,
    pub nodes: HashMap<String, Node>,
}

impl Tree {
    /// Reading a tree
    ///
    /// Note: Usually one reads this from a file, not used directly like shown here.
    ///
    /// ```
    /// let tree_bytes = [0, 0, 2, 182, 159, 84, 114, 101, 101, 86, 48, 50, 50, 0, 1, 0, 30, 255, 11, 1, 245, 0, 0, 0, 20, 0, 0, 65, 237, 0, 0, 0, 0, 92, 197, 219, 103, 0, 0, 0, 0, 16, 90, 33, 177, 75, 0, 1, 132, 2, 77, 81, 191, 0, 0, 0, 4, 28, 0, 15, 48, 0, 3, 17, 16, 31, 0, 193, 92, 197, 219, 84, 0, 0, 0, 0, 48, 246, 52, 114, 17, 0, 67, 0, 0, 2, 1, 9, 0, 145, 8, 115, 111, 109, 101, 102, 105, 108, 101, 16, 0, 17, 2, 6, 0, 2, 2, 0, 20, 1, 35, 0, 244, 30, 40, 100, 97, 56, 97, 48, 48, 51, 53, 55, 54, 52, 51, 100, 52, 56, 49, 98, 53, 98, 52, 54, 99, 57, 100, 99, 57, 99, 52, 49, 50, 55, 55, 98, 51, 53, 98, 57, 101, 56, 53, 1, 0, 0, 0, 53, 0, 6, 2, 0, 22, 12, 11, 0, 15, 2, 0, 13, 4, 3, 1, 41, 129, 164, 3, 1, 60, 92, 158, 217, 58, 0, 5, 103, 0, 5, 9, 0, 146, 0, 1, 0, 0, 4, 2, 77, 81, 220, 11, 0, 2, 2, 0, 5, 22, 1, 3, 67, 0, 5, 16, 0, 50, 89, 212, 77, 34, 0, 85, 0, 8, 0, 0, 16, 182, 0, 177, 10, 116, 111, 112, 95, 102, 111, 108, 100, 101, 114, 89, 0, 15, 16, 1, 3, 255, 25, 99, 48, 53, 55, 49, 53, 51, 55, 100, 53, 55, 100, 57, 52, 56, 56, 49, 54, 52, 51, 48, 51, 57, 53, 48, 100, 102, 100, 101, 100, 53, 99, 98, 54, 99, 102, 99, 100, 50, 48, 16, 1, 3, 19, 39, 121, 0, 15, 2, 0, 116, 80, 0, 0, 0, 0, 0];
    /// let tree = arq::tree::Tree::new(&tree_bytes, arq::compression::CompressionType::LZ4).unwrap();
    /// assert_eq!(tree.version, 22);
    /// ```
    pub fn new(compressed_content: &[u8], compression_type: CompressionType) -> Result<Tree> {
        let content = CompressionType::decompress(compressed_content, compression_type)?;
        let mut reader = BufReader::new(std::io::Cursor::new(content));
        let tree_header = reader.read_bytes(8)?;
        assert_eq!(tree_header[..5], [84, 114, 101, 101, 86]);
        let version = std::str::from_utf8(&tree_header[5..])?.parse::<u32>()?;

        let xattrs_compression_type = reader.read_arq_compression_type()?;
        let acl_compression_type = reader.read_arq_compression_type()?;
        let xattrs_blob_key = blob::BlobKey::new(&mut reader)?;
        let xattrs_size = reader.read_arq_u64()?; //TODO(nlopes): what is this used for?
        let acl_blob_key = blob::BlobKey::new(&mut reader)?;
        let uid = reader.read_arq_i32()?;
        let gid = reader.read_arq_i32()?;
        let mode = reader.read_arq_i32()?;
        let mtime_sec = reader.read_arq_i64()?;
        let mtime_nsec = reader.read_arq_i64()?;
        let flags = reader.read_arq_i64()?;
        let finder_flags = reader.read_arq_i32()?;
        let extended_finder_flags = reader.read_arq_i32()?;
        let st_dev = reader.read_arq_i32()?;
        let st_ino = reader.read_arq_i32()?;
        let st_nlink = reader.read_arq_u32()?;
        let st_rdev = reader.read_arq_i32()?;
        let ctime_sec = reader.read_arq_i64()?;
        let ctime_nsec = reader.read_arq_i64()?;
        let st_blocks = reader.read_arq_i64()?;
        let st_blksize = reader.read_arq_u32()?;
        let create_time_sec = reader.read_arq_i64()?;
        let create_time_nsec = reader.read_arq_i64()?;
        let mut missing_node_count = reader.read_arq_u32()?;

        let mut missing_nodes = Vec::new();
        while missing_node_count > 0 {
            let node_name = reader.read_arq_string()?;
            missing_nodes.push(node_name);
            missing_node_count -= 1;
        }

        let mut node_count = reader.read_arq_u32()?;
        let mut nodes = HashMap::new();
        while node_count > 0 {
            let node_name = reader.read_arq_string()?;
            assert!(!node_name.is_empty());

            let node = Node::new(&mut reader)?;
            nodes.insert(node_name, node);
            node_count -= 1;
        }

        Ok(Tree {
            version,
            xattrs_compression_type,
            acl_compression_type,
            xattrs_blob_key,
            xattrs_size,
            acl_blob_key,
            uid,
            gid,
            mode,
            mtime_sec,
            mtime_nsec,
            flags,
            finder_flags,
            extended_finder_flags,
            st_dev,
            st_ino,
            st_nlink,
            st_rdev,
            ctime_sec,
            ctime_nsec,
            st_blocks,
            st_blksize,
            create_time_sec,
            create_time_nsec,
            missing_nodes,
            nodes,
        })
    }
}

pub type ParentCommits = HashMap<String, bool>;
pub type FailedFile = (String, String);

/// Commit
///
/// A "commit" contains the following bytes:
///
/// ```ascii
///     43 6f 6d 6d 69 74 56 30 31 32      "CommitV012"
///     [String:"<author>"]
///     [String:"<comment>"]
///     [UInt64:num_parent_commits]        (this is always 0 or 1)
///     (
///         [String:parent_commit_sha1] /* can't be null */
///         [Bool:parent_commit_encryption_key_stretched]] /* present for Commit version >= 4 */
///     )   /* repeat num_parent_commits times */
///     [String:tree_sha1]] /* can't be null */
///     [Bool:tree_encryption_key_stretched]] /* present for Commit version >= 4 */
///     [Bool:tree_is_compressed] /* present for Commit version 8 and 9 only; indicates Gzip compression or none */
///     [CompressionType:tree_compression_type] /* present for Commit version >= 10 */
///
///     [String:"file://<hostname><path_to_folder>"]
///     [String:"<merge_common_ancestor_sha1>"] /* only present for Commit version 7 or *older* (was never used) */
///     [Bool:is_merge_common_ancestor_encryption_key_stretched] /* only present for Commit version 4 to 7 */
///     [Date:creation_date]
///     [UInt64:num_failed_files] /* only present for Commit version 3 or later */
///     (
///         [String:"<relative_path>"] /* only present for Commit version 3 or later */
///         [String:"<error_message>"] /* only present for Commit version 3 or later */
///     )   /* repeat num_failed_files times */
///     [Bool:has_missing_nodes] /* only present for Commit version 8 or later */
///     [Bool:is_complete] /* only present for Commit version 9 or later */
///     [Data:config_plist_xml] /* a copy of the XML file as described above */
///     [String:arq_version] /* the version of the Arq app that created this Commit */
/// ```
///
/// The SHA1 of the most recent Commit is stored in
/// `/<computer_uuid>/bucketdata/<folder_uuid>/refs/heads/master` appended with a "Y" for
/// historical reasons.
///
/// In addition, Arq writes a file in
/// `/<computer_uuid>/bucketdata/<folder_uuid>/refs/logs/master` each time a new Commit is
/// created (the filename is a timestamp). It's a plist containing the previous and current
/// Commit SHA1s, the SHA1 of the pack file containing the new Commit, and whether the new
/// Commit is a "rewrite" (because the user deleted a backup record for instance).
pub struct Commit {
    pub version: u32,
    pub author: String,
    pub comment: String,
    pub parent_commits: ParentCommits,
    pub tree_sha1: String,
    pub tree_encryption_key_stretched: bool,
    pub tree_compression_type: CompressionType,
    pub folder_path: String,
    pub creation_date: Date,
    pub failed_files: Vec<FailedFile>,
    pub has_missing_nodes: bool,
    pub is_complete: bool,
    pub config_plist_xml: Vec<u8>,
    pub arq_version: String,
}

impl Commit {
    pub fn is_commit(content: &[u8]) -> bool {
        content[..10] == [67, 111, 109, 109, 105, 116, 86, 48, 49, 50] // CommitV012
    }

    pub fn new<R: ArqRead>(mut reader: R) -> Result<Commit> {
        let header = reader.read_bytes(10)?;
        assert_eq!(header[..7], [67, 111, 109, 109, 105, 116, 86]); // CommitV
        let version = std::str::from_utf8(&header[7..])?.parse::<u32>()?;

        let author = reader.read_arq_string()?;
        let comment = reader.read_arq_string()?;

        let mut num_parent_commits = reader.read_arq_u64()?;
        assert!(num_parent_commits == 0 || num_parent_commits == 1);

        let mut parent_commits: ParentCommits = HashMap::new();
        while num_parent_commits > 0 {
            let sha1 = reader.read_arq_string()?;
            let encryption_key_stretched = reader.read_arq_bool()?;

            parent_commits.insert(sha1, encryption_key_stretched);
            num_parent_commits -= 1;
        }

        let tree_sha1 = reader.read_arq_string()?;
        let tree_encryption_key_stretched = reader.read_arq_bool()?;
        let tree_compression_type = reader.read_arq_compression_type()?;
        let folder_path = reader.read_arq_string()?;
        let creation_date = reader.read_arq_date()?;

        let mut num_failed_files = reader.read_arq_u64()?;
        let mut failed_files = Vec::new();
        while num_failed_files > 0 {
            let relative_path = reader.read_arq_string()?;
            let error_message = reader.read_arq_string()?;

            failed_files.push((relative_path, error_message));
            num_failed_files -= 1;
        }

        let has_missing_nodes = reader.read_arq_bool()?;
        let is_complete = reader.read_arq_bool()?;
        let config_plist_xml = reader.read_arq_data()?;
        let arq_version = reader.read_arq_string()?;

        Ok(Commit {
            version,
            author,
            comment,
            parent_commits,
            tree_sha1,
            tree_encryption_key_stretched,
            tree_compression_type,
            folder_path,
            creation_date,
            failed_files,
            has_missing_nodes,
            is_complete,
            config_plist_xml,
            arq_version,
        })
    }
}
