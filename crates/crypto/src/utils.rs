//! Utility functions for cryptographic operations.

use rand::RngCore;
use zeroize::Zeroize;

use crate::aes::{AES_IV_SIZE, AES_KEY_SIZE};

/// Generate cryptographically secure random bytes.
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a random 32-byte AES key.
pub fn generate_file_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random 12-byte IV.
pub fn generate_iv() -> [u8; AES_IV_SIZE] {
    let mut iv = [0u8; AES_IV_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

/// Convert a hex string to bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Convert bytes to a hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Zeroize sensitive data in a byte slice.
pub fn clear_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

/// Generate a random UUID v4 string.
pub fn generate_uuid_v4() -> String {
    let bytes = generate_random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6] & 0x0f, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Detect MIME type from file extension.
///
/// Returns a static string to avoid heap allocation on hot paths.
pub fn mime_from_extension(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("");
    // Use eq_ignore_ascii_case to avoid heap-allocating a lowercase copy
    MIME_EXTENSIONS
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(ext))
        .map(|(_, mime)| *mime)
        .unwrap_or("application/octet-stream")
}

const MIME_EXTENSIONS: &[(&str, &str)] = &[
    ("txt", "text/plain"),
    ("html", "text/html"),
    ("htm", "text/html"),
    ("css", "text/css"),
    ("js", "application/javascript"),
    ("mjs", "application/javascript"),
    ("json", "application/json"),
    ("xml", "application/xml"),
    ("pdf", "application/pdf"),
    ("zip", "application/zip"),
    ("gz", "application/gzip"),
    ("gzip", "application/gzip"),
    ("tar", "application/x-tar"),
    ("7z", "application/x-7z-compressed"),
    ("rar", "application/x-rar-compressed"),
    ("doc", "application/msword"),
    ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("xls", "application/vnd.ms-excel"),
    ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("ppt", "application/vnd.ms-powerpoint"),
    ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("svg", "image/svg+xml"),
    ("webp", "image/webp"),
    ("ico", "image/x-icon"),
    ("bmp", "image/bmp"),
    ("tiff", "image/tiff"),
    ("tif", "image/tiff"),
    ("mp3", "audio/mpeg"),
    ("wav", "audio/wav"),
    ("ogg", "audio/ogg"),
    ("flac", "audio/flac"),
    ("aac", "audio/aac"),
    ("mp4", "video/mp4"),
    ("webm", "video/webm"),
    ("avi", "video/x-msvideo"),
    ("mov", "video/quicktime"),
    ("mkv", "video/x-matroska"),
    ("csv", "text/csv"),
    ("md", "text/markdown"),
    ("yaml", "application/yaml"),
    ("yml", "application/yaml"),
    ("toml", "application/toml"),
    ("wasm", "application/wasm"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex_str = bytes_to_hex(&original);
        let decoded = hex_to_bytes(&hex_str).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_to_bytes_lowercase() {
        let result = hex_to_bytes("deadbeef").unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_to_bytes_odd_length_fails() {
        let result = hex_to_bytes("abc");
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_bytes_invalid_chars_fails() {
        let result = hex_to_bytes("zzzz");
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_bytes_empty_string() {
        let result = hex_to_bytes("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn generate_file_key_returns_32_bytes() {
        let key = generate_file_key();
        assert_eq!(key.len(), AES_KEY_SIZE);
    }

    #[test]
    fn generate_file_key_is_random() {
        let key1 = generate_file_key();
        let key2 = generate_file_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn generate_iv_returns_12_bytes() {
        let iv = generate_iv();
        assert_eq!(iv.len(), AES_IV_SIZE);
    }

    #[test]
    fn generate_iv_is_random() {
        let iv1 = generate_iv();
        let iv2 = generate_iv();
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn generate_random_bytes_correct_length() {
        for len in [0, 1, 16, 32, 64, 256] {
            let bytes = generate_random_bytes(len);
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn clear_bytes_zeros_all() {
        let mut buf = vec![0xFF; 32];
        clear_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn clear_bytes_empty_slice() {
        let mut buf: Vec<u8> = vec![];
        clear_bytes(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn generate_uuid_v4_format() {
        let uuid = generate_uuid_v4();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(14), Some('4'));
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(matches!(variant_char, '8' | '9' | 'a' | 'b'));
    }

    #[test]
    fn mime_from_extension_known() {
        assert_eq!(mime_from_extension("photo.png"), "image/png");
        assert_eq!(mime_from_extension("doc.pdf"), "application/pdf");
        assert_eq!(mime_from_extension("song.mp3"), "audio/mpeg");
        assert_eq!(mime_from_extension("video.mp4"), "video/mp4");
        assert_eq!(mime_from_extension("page.html"), "text/html");
    }

    #[test]
    fn mime_from_extension_case_insensitive() {
        assert_eq!(mime_from_extension("IMAGE.PNG"), "image/png");
        assert_eq!(mime_from_extension("Doc.PDF"), "application/pdf");
    }

    #[test]
    fn mime_from_extension_unknown() {
        assert_eq!(mime_from_extension("file.xyz"), "application/octet-stream");
        assert_eq!(mime_from_extension("noext"), "application/octet-stream");
    }
}
