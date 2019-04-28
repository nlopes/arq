use plist::serde::deserialize;
use std::io::{BufRead, Seek};

use crate::error::Result;

/// Contains metadata information with user name and computer name.
///
/// This is so that you can identify which backup set is which when you browse the backup
/// set in your cloud storage account.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputerInfo {
    pub user_name: String,
    pub computer_name: String,
    /// uuid is optional (when deserializing) but we set it to whatever the user provides
    #[serde(skip)]
    pub uuid: String,
}

impl ComputerInfo {
    /// Deserialize reader content (plist format) into a `ComputerInfo`.
    /// # Examples:
    ///
    /// let info = ComputerInfo::new("someid", reader)?;
    /// println!("{}", info.computer_name);
    pub fn new<T: BufRead + Seek>(reader: T, uuid: String) -> Result<ComputerInfo> {
        let mut computer_info: ComputerInfo = deserialize(reader)?;
        computer_info.uuid = uuid;
        Ok(computer_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_valid_reader_content() {
        let raw = "
<plist> \
  <dict> \
    <key>userName</key> \
    <string>SOMEUSER</string> \
    <key>computerName</key> \
    <string>SOMECOMPUTER</string> \
  </dict> \
</plist> \
";
        let info_res =
            ComputerInfo::new(Cursor::new(raw.as_bytes()), "someuuid".to_string());
        let info = info_res.unwrap();
        assert_eq!(info.computer_name, "SOMECOMPUTER");
        assert_eq!(info.uuid, "someuuid");
    }

    #[test]
    #[should_panic]
    fn test_invalid_reader_content() {
        let raw = "
<plist> \
  <dict> \
    <key>userName</key> \
    <key>computerName</key> \
    <string>SOMECOMPUTER</string> \
  </dict> \
</plist> \
";
        ComputerInfo::new(Cursor::new(raw.as_bytes()), "someuuid".to_string()).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_empty_computer_info() {
        ComputerInfo::new(Cursor::new("".as_bytes()), "someuuid".to_string()).unwrap();
    }
}
