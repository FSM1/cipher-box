//! Keychain operations for secure refresh token storage.
//!
//! Uses the `keyring` crate with apple-native feature for macOS Keychain integration.
//! Refresh tokens are stored in the system Keychain, never on disk.

use keyring::Entry;
use thiserror::Error;

/// Keychain service name matching the Tauri app identifier.
const SERVICE_NAME: &str = "com.cipherbox.desktop";

/// Special username for storing the last logged-in user ID.
const LAST_USER_ID_KEY: &str = "last_user_id";

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("Keychain operation failed: {0}")]
    OperationFailed(String),
}

impl From<keyring::Error> for KeychainError {
    fn from(err: keyring::Error) -> Self {
        KeychainError::OperationFailed(err.to_string())
    }
}

/// Store a refresh token in the macOS Keychain for the given user ID.
pub fn store_refresh_token(user_id: &str, token: &str) -> Result<(), KeychainError> {
    let entry = Entry::new(SERVICE_NAME, user_id)?;
    entry.set_password(token)?;
    Ok(())
}

/// Retrieve the refresh token from the macOS Keychain for the given user ID.
///
/// Returns `None` if no entry exists (user never logged in or was logged out).
pub fn get_refresh_token(user_id: &str) -> Result<Option<String>, KeychainError> {
    let entry = Entry::new(SERVICE_NAME, user_id)?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::from(e)),
    }
}

/// Delete the refresh token from the macOS Keychain for the given user ID.
///
/// Idempotent: ignores `NoEntry` error (already deleted or never stored).
pub fn delete_refresh_token(user_id: &str) -> Result<(), KeychainError> {
    let entry = Entry::new(SERVICE_NAME, user_id)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already deleted, idempotent
        Err(e) => Err(KeychainError::from(e)),
    }
}

/// Store the user ID so we can find the Keychain entry on next app launch.
///
/// Uses a fixed key "last_user_id" to store which user was last logged in.
pub fn store_user_id(user_id: &str) -> Result<(), KeychainError> {
    let entry = Entry::new(SERVICE_NAME, LAST_USER_ID_KEY)?;
    entry.set_password(user_id)?;
    Ok(())
}

/// Retrieve the last logged-in user ID for silent refresh on app launch.
///
/// Returns `None` if no user has logged in before.
pub fn get_last_user_id() -> Result<Option<String>, KeychainError> {
    let entry = Entry::new(SERVICE_NAME, LAST_USER_ID_KEY)?;
    match entry.get_password() {
        Ok(id) => Ok(Some(id)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::from(e)),
    }
}
