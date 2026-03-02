//! Shared utility functions used across command modules.

/// Extract the user ID (`sub` claim) from a JWT access token.
///
/// Decodes the JWT payload (base64url) without verification -- the server
/// already verified the token, we just need the `sub` field for Keychain lookup.
pub(crate) fn extract_user_id_from_jwt(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode the payload (second part) -- base64url encoding
    let payload = parts[1];
    // base64url: replace - with + and _ with /, then add padding
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let standard = padded.replace('-', "+").replace('_', "/");

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &standard)
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;

    let json: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| format!("Failed to parse JWT payload: {}", e))?;

    json["sub"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "JWT payload missing 'sub' claim".to_string())
}

/// Derive an uncompressed secp256k1 public key (65 bytes, 0x04 prefix) from a 32-byte private key.
///
/// Used for ECIES encryption/decryption operations.
pub(crate) fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let sk = ecies::SecretKey::parse_slice(private_key)
        .map_err(|e| format!("Invalid secp256k1 private key: {:?}", e))?;
    let pk = ecies::PublicKey::from_secret_key(&sk);
    Ok(pk.serialize().to_vec()) // 65-byte uncompressed format
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_user_id_from_jwt() {
        // Create a mock JWT with a known sub claim
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"user-123-abc","iat":1700000000}
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"sub\":\"user-123-abc\",\"iat\":1700000000}",
        );
        let token = format!("{}.{}.fake-signature", header, payload);

        let user_id = extract_user_id_from_jwt(&token).unwrap();
        assert_eq!(user_id, "user-123-abc");
    }

    #[test]
    fn test_extract_user_id_invalid_jwt() {
        let result = extract_user_id_from_jwt("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_user_id_missing_sub() {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"iat\":1700000000}",
        );
        let token = format!("{}.{}.fake-signature", header, payload);

        let result = extract_user_id_from_jwt(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sub"));
    }

    #[test]
    fn test_derive_public_key() {
        // Use a known private key and verify the public key is 65 bytes with 0x04 prefix
        let private_key = hex::decode(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();

        let public_key = derive_public_key(&private_key).unwrap();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04); // Uncompressed prefix
    }

    #[test]
    fn test_derive_public_key_invalid_size() {
        let result = derive_public_key(&[0u8; 16]); // Too short
        assert!(result.is_err());
    }
}
