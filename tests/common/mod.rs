use std::path::{Path, PathBuf};

pub const ENCRYPTION_PASSWORD: &str = "evu";
pub const COMPUTER: &str = "AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D";
pub const FOLDER: &str = "7C19E8AF-FFE9-4952-B1E1-8D5181012BB1";

fn get_fixtures_path() -> &'static Path {
    Path::new("./fixtures")
}

pub fn get_computer_path() -> PathBuf {
    get_fixtures_path().join(COMPUTER)
}

pub fn get_folder_path() -> PathBuf {
    get_computer_path().join("buckets").join(FOLDER)
}

pub fn get_encryptionv3_path() -> PathBuf {
    get_computer_path().join("encryptionv3.dat")
}
