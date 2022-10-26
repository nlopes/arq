//! Various structs dealing with encrypted objects
//!
//! The 2 main objects we include are:
//!
//! - EncryptionDat
//! - EncryptedObject
use std;
use std::io::{BufRead, Seek};
use std::str;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use ring::pbkdf2;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::type_utils::ArqRead;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

fn calculate_hmacsha256(secret: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn calculate_sha1sum(message: &[u8]) -> Vec<u8> {
    let mut sha = Sha1::new();
    sha.update(message);
    sha.finalize().to_vec()
}

pub trait Validation {
    fn validate(&self, _: usize, _: &str);
}

pub type Header = Vec<u8>;

impl Validation for Header {
    fn validate(&self, count: usize, content: &str) {
        match str::from_utf8(&self[0..count]) {
            Ok(header_str) => {
                if header_str != content {
                    panic!("File contains wrong header: {}", header_str);
                }
            }
            Err(err) => panic!("Couldn't convert to string ({})", err),
        };
    }
}

/// Encryption Dat File
/// -------------------
///
/// The first time you add a folder to Arq for backing up, it prompts you to choose
/// an encryption password.  Arq creates 3 randomly-generated encryption keys.  The
/// first key is used for encrypting/decrypting; the second key is used for
/// creating HMACs; the third key is concatenated with file data to calculate a
/// SHA1 identifier.
///
/// Arq stores those keys, encrypted with the encryption password you chose, in a
/// file called /<computerUUID>/encryptionv3.dat. You can change your encryption
/// password at any time by decrypting this file with the old encryption password
/// and then re-encrypting it with your new encryption password.
///
/// The encryptionv3.dat file format is:
///
/// ```ascii
/// header                      45 4e 43 52 ENCR
///                             59 50 54 49 YPTI
///                             4f 4e 56 32 ONV2
/// salt                        xx xx xx xx
///                             xx xx xx xx
/// HMACSHA256                  xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
/// IV                          xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
///                             xx xx xx xx
/// encrypted master keys       xx xx xx xx
///                             ...
///```
///
///
/// To create the encryptionv3.dat file:
/// 1. Generate a random salt.
/// 2. Generate a random IV.
/// 3. Generate 3 random 32-byte "master keys" (96 bytes total).
/// 4. Derive 64-byte encryption key from user-supplied encryption password using PBKDF2/HMACSHA1 (200000 rounds) and the salt from step 1.
/// 5. Encrypt the master keys with AES256-CBC using the first 32 bytes of the derived key from step 4 and IV from step 2.
/// 6. Calculate the HMAC-SHA256 of (IV + encrypted master keys) using the second 32 bytes of the derived key from step 4.
/// 7. Concatenate the items as described in the file format shown above.
//
/// To get the 3 "master keys":
/// 1. Copy salt from the 8 bytes after the header.
/// 2. Derive 64-byte encryption key from user-supplied encryption password using PBKDF2/HMACSHA1 (200000 rounds) and the salt from step 1.
/// 3. Calculate HMAC-SHA256 of (IV + encrypted master keys) using second 32 bytes of key from step 2, and verify against HMAC-SHA256 in the file.
/// 4. Decrypt the ciphertext using the first 32 bytes of the derived key from step 2 to get 3 32-byte "master keys".
///
/// Note: We use HMACSHA1 as the PRF with PBKDF2 because that's the only one available on
/// Windows (in .NET).
///
///
/// Note: If you created your backup set with an older version of Arq, you may have an
/// encryptionv2.dat file instead of an encryptionv3.dat file. The encryptionv2.dat file
/// is the same format as encryptionv3.dat, but there are only 2 256-bit master keys. In
/// this case Arq adds the computerUUID (instead of the 3rd key) to object data when
/// calculating the SHA1 hash (see "Content-Addressable Storage" above). Arq changed to
/// using a third secret key for salting the hash instead of a known value to address a
/// privacy issue.

pub struct EncryptionDat {
    salt: Vec<u8>,
    hmac_sha256: Vec<u8>,
    iv: Vec<u8>,
    encryption_key: Vec<u8>,
    pub master_keys: Vec<Vec<u8>>,
}

impl EncryptionDat {
    fn parse_master_keys(master_keys: Vec<u8>) -> Vec<Vec<u8>> {
        let master_key_1 = &master_keys[0..32];
        let master_key_2 = &master_keys[32..64];
        let master_key_3 = &master_keys[64..96];

        vec![
            master_key_1.to_vec(),
            master_key_2.to_vec(),
            master_key_3.to_vec(),
        ]
    }

    fn derive_encryption_key(password: &[u8], salt: &[u8], result: &mut [u8]) {
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA1,
            std::num::NonZeroU32::new(200_000).unwrap(), // this unwrap will always succeed
            salt,
            password,
            result,
        );
    }

    pub fn new<R: BufRead + Seek>(mut reader: R, password: &str) -> Result<EncryptionDat> {
        let header = reader.read_bytes(12)?;
        assert_eq!(header, [69, 78, 67, 82, 89, 80, 84, 73, 79, 78, 86, 50]); // ENCRYPTIONV2
        let salt = reader.read_bytes(8)?;
        let hmacsha256 = reader.read_bytes(32)?;
        let iv = reader.read_bytes(16)?;
        let mut encrypted_master_keys = reader.read_bytes(112)?;

        let mut encryption_key: [u8; 64] = [0u8; 64];
        Self::derive_encryption_key(password.as_bytes(), &salt[..], &mut encryption_key);

        let iv_and_keys = [&iv[..], &encrypted_master_keys[..]].concat();
        let calculated_hmacsha256 = calculate_hmacsha256(&encryption_key[32..64], &iv_and_keys)?;
        if calculated_hmacsha256 != hmacsha256 {
            return Err(Error::WrongPassword);
        }

        let _ = Aes256CbcDec::new_from_slices(&encryption_key[0..32], &iv[..])?
            .decrypt_padded_mut::<Pkcs7>(&mut encrypted_master_keys)?;

        Ok(EncryptionDat {
            salt: salt.to_vec(),
            hmac_sha256: hmacsha256.to_vec(),
            iv: iv.to_vec(),
            encryption_key: encryption_key.to_vec(),
            master_keys: Self::parse_master_keys(encrypted_master_keys),
        })
    }
}

/// EncryptedObject
/// ---------------
///
/// We use the term "EncryptedObject" throughout this document as shorthand to
/// describe an object containing data in the following format:
///
///```ascii
/// header                              41 52 51 4f  ARQO
/// HMACSHA256                          xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
/// master IV                           xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
///                                     xx xx xx xx
/// encrypted data IV + session key     xx xx xx xx
///                                     ...
/// ciphertext                          xx xx xx xx
///                                     ...
///```
///
/// To create an EncryptedObject:
/// 1. Generate a random 256-bit session key (Arq reuses it for up to 256 objects before replacing it).
/// 2. Generate a random "data IV".
/// 3. Encrypt plaintext with AES/CBC using session key and data IV.
/// 4. Generate a random "master IV".
/// 5. Encrypt (data IV + session key) with AES/CBC using the first "master key" from the Encryption Dat File and the "master IV".
/// 4. Calculate HMAC-SHA256 of (master IV + "encrypted data IV + session key" + ciphertext) using the second 256-bit "master key".
/// 7. Assemble the data in the format shown above.

/// To get the plaintext:
/// 1. Calculate HMAC-SHA256 of (master IV + "encrypted data IV + session key" + ciphertext) and verify against HMAC-SHA256 in the file using the second "master key" from the Encryption Dat File.
/// 2. Ensure the calculated HMAC-SHA256 matches the value in the object header.
/// 3. Decrypt "encrypted data IV + session key" using the first "master key" from the Encryption Dat File and the "master IV".
/// 4. Decrypt the ciphertext using the session key and data IV.
pub struct EncryptedObject {
    hmac_sha256: Vec<u8>, //TODO: can we make this [u8; size?]
    master_iv: Vec<u8>,
    encrypted_data_iv_session: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedObject {
    pub fn new<R: ArqRead + BufRead>(mut reader: R) -> Result<EncryptedObject> {
        let header = reader.read_bytes(4)?.to_vec();
        assert_eq!(header, [65, 82, 81, 79]); // ARQO
        let hmac_sha256 = reader.read_bytes(32)?.to_vec();
        let master_iv = reader.read_bytes(16)?.to_vec();
        let encrypted_data_iv_session = reader.read_bytes(64)?.to_vec();
        let mut ciphertext: Vec<u8> = Vec::new();
        reader.read_to_end(&mut ciphertext)?;

        Ok(EncryptedObject {
            hmac_sha256,
            master_iv,
            encrypted_data_iv_session,
            ciphertext,
        })
    }

    pub fn validate(&self, master_key: &[u8]) -> Result<()> {
        let mut master_iv_and_data = self.master_iv.clone();
        master_iv_and_data.append(&mut self.encrypted_data_iv_session.clone());
        master_iv_and_data.append(&mut self.ciphertext.clone());
        let calculated_hmacsha256 = calculate_hmacsha256(master_key, &master_iv_and_data)?;
        assert_eq!(calculated_hmacsha256, self.hmac_sha256);
        Ok(())
    }

    pub fn decrypt(&self, master_key: &[u8]) -> Result<Vec<u8>> {
        let mut enc_data_iv_session = self.encrypted_data_iv_session.clone();
        let master_iv = self.master_iv.clone();

        let data_iv_session = Aes256CbcDec::new_from_slices(master_key, &master_iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut enc_data_iv_session)?;
        let data_iv = &data_iv_session[0..16];
        let session_key = &data_iv_session[16..48];

        let mut ciphertext = self.ciphertext.clone();
        let content = Aes256CbcDec::new_from_slices(session_key, data_iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)?;
        Ok(content.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_hmacsha256() {
        let secret = "secret".as_bytes();
        let message = "message".as_bytes();

        let result = [
            139, 95, 72, 112, 41, 149, 193, 89, 140, 87, 61, 177, 226, 24, 102, 169, 184, 37, 212,
            167, 148, 209, 105, 215, 6, 10, 3, 96, 87, 150, 54, 11,
        ]
        .to_vec();

        assert_eq!(result, calculate_hmacsha256(secret, message).unwrap());
    }

    #[test]
    fn test_calculate_sha1sum() {
        let message = "message".as_bytes();
        println!("{:#?}", calculate_sha1sum(message));
        assert_eq!(
            hex!("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d"),
            calculate_sha1sum(message)[..]
        );
    }
}
