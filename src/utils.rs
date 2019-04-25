/// Converts an array of u8 into a string of hex.
pub fn convert_to_hex_string(array: &[u8]) -> String {
    array.iter().map(|a| format!("{:02x}", a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_to_hex_string() {
        let data = vec![12, 34, 11, 56, 78, 92];
        assert_eq!(convert_to_hex_string(&data), "0c220b384e5c");
        assert_eq!(convert_to_hex_string(&[]), "");
    }
}
