use std;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

use crate::blob;
use crate::error::Result;
use crate::lz4;
use crate::type_utils::{ArqCompressionType, ArqDate, ArqRead};

pub struct Node {
    pub is_tree: bool,
    pub tree_contains_missing_items: bool,
    pub data_compression_type: ArqCompressionType,
    pub xattrs_compression_type: ArqCompressionType,
    pub acl_compression_type: ArqCompressionType,
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

pub struct Tree {
    pub version: u32,
    pub xattrs_compression_type: ArqCompressionType,
    pub acl_compression_type: ArqCompressionType,
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
    pub fn new(compressed_content: &[u8], compression_type: ArqCompressionType) -> Result<Tree> {
        let content: Vec<u8> = match compression_type {
            ArqCompressionType::LZ4 => lz4::decompress(compressed_content)?,
            ArqCompressionType::Gzip => unimplemented!(),
            ArqCompressionType::None => compressed_content.to_owned(),
        };

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
            assert_eq!(node_name.is_empty(), false);

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

pub struct Commit {
    pub version: u32,
    pub author: String,
    pub comment: String,
    pub parent_commits: ParentCommits,
    pub tree_sha1: String,
    pub tree_encryption_key_stretched: bool,
    pub tree_compression_type: ArqCompressionType,
    pub folder_path: String,
    pub creation_date: ArqDate,
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
