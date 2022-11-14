use crate::common::get_folder_path;

mod common;

#[test]
fn test_load_computer_info() {
    use arq::computer::ComputerInfo;

    let computer_path = common::get_computer_path();
    let reader =
        std::io::BufReader::new(std::fs::File::open(computer_path.join("computerinfo")).unwrap());
    let ci = ComputerInfo::new(
        reader,
        computer_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
    )
    .unwrap();
    assert_eq!(ci.computer_name, "my-computer-name");
    assert_eq!(ci.user_name, "my-username");
    assert_eq!(ci.uuid, "AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D");
}

#[test]
fn test_loading_encrypted_object_dat() {
    use arq::{folder::Folder, object_encryption::EncryptionDat};
    use std::io::{BufRead, BufReader};

    let ec = common::get_encryptionv3_path();
    let mut reader = BufReader::new(std::fs::File::open(&ec).unwrap());
    let mut buf = Vec::new();
    let _ = reader.read_until(b'-', &mut buf);
    let reader = BufReader::new(std::fs::File::open(ec).unwrap());
    let ec_dat = EncryptionDat::new(reader, common::ENCRYPTION_PASSWORD).unwrap();

    let mut folder = BufReader::new(std::fs::File::open(get_folder_path()).unwrap());
    let _ = Folder::new(&mut folder, &ec_dat.master_keys).unwrap();
}

#[test]
fn test_generate_encryption_v3_dat() {
    use arq::object_encryption::EncryptionDat;
    let _ = EncryptionDat::new(
        std::io::Cursor::new(&EncryptionDat::generate(common::ENCRYPTION_PASSWORD).unwrap()),
        common::ENCRYPTION_PASSWORD,
    )
    .unwrap();
}
