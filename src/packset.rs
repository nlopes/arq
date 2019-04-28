use byteorder::{NetworkEndian, ReadBytesExt};
use std;
use std::io::{BufRead, Cursor, Seek, SeekFrom};

use crate::error::Result;
use crate::object_encryption::{calculate_sha1sum, EncryptedObject};
use crate::type_utils::{ArqRead, ArqCompressionType};
use crate::utils::convert_to_hex_string;
use crate::lz4;

pub struct Pack {
    pub version: Vec<u8>,
    pub objects: Vec<PackObject>,
}

pub struct PackObject {
    pub mimetype: String,
    pub name: String,
    pub data: EncryptedObject,
}

pub struct PackIndex {
    pub version: Vec<u8>,
    pub fanout: Vec<Vec<u8>>,
    pub objects: Vec<PackIndexObject>,

    pub glacier_archive_id_present: bool,
    // TODO(nlopes): maybe this should be String
    pub glacier_archive_id: Vec<u8>,
    pub glacier_pack_size: usize,
}

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
        let mut _buf = Vec::with_capacity(21);
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

    pub fn original(&self, compression_type: &ArqCompressionType, master_key: &[u8]) -> Result<Vec<u8>> {
        let decrypted = self.data.decrypt(master_key)?;

        let content: Vec<u8> = match compression_type {
            ArqCompressionType::LZ4 => lz4::decompress(&decrypted)?,
            ArqCompressionType::Gzip => unimplemented!(),
            ArqCompressionType::None => decrypted.to_owned(),
        };
        Ok(content)
    }
}
