//! The one decode of a facade command from its JS value, and the one encode of
//! what it answers. Both types are the engine's own, typed for TS by tsify
//! (blueprint/web-client.md "WASM packaging and the type boundary").
//!
//! Serde buffers an internally tagged value whole before it picks the variant,
//! and frees that buffer unwiped when a later field refuses. So a command that
//! carries a secret decodes with a placeholder in the secret's place, and the
//! secret is taken into a zeroizing buffer only once the rest has decoded
//! (AGENTS.md rule 7). A refusal names no field value: a value can be a name
//! the member typed.

use cipherbox_engine::content::ByoBearer;
use cipherbox_engine::facade::{Command, CommandOutcome};
use cipherbox_engine::grants::MAX_FRAGMENT_TEXT_LEN;
use cipherbox_engine::wire::{KEEP_STORED_BEARER, bearer_from_bytes};
use js_sys::{ArrayBuffer, JsString, Object, Reflect, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The one serializer configuration, matching the tsify attributes on the
/// engine types: `u64` as `bigint`, an absent `Option` as `null`.
const SERIALIZER: Serializer = Serializer::new()
    .serialize_large_number_types_as_bigints(true)
    .serialize_missing_as_null(true);

const BEARER_PATH: [&str; 3] = ["settings", "byo", "accessToken"];

fn refused() -> JsError {
    JsError::new("the command does not decode")
}

/// Decodes one command. Refuses an unknown `kind`, an unknown field, and a
/// field of the wrong type.
pub fn decode_command(command: &JsValue) -> Result<Command, JsError> {
    let kind = field(command, "kind");
    if kind == "claimInviteLink" {
        let fragment = field(command, "fragment");
        let mut decoded = decode(&with_placeholder(command, &["fragment"], &"".into())?)?;
        let Command::ClaimInviteLink { fragment: slot, .. } = &mut decoded else {
            return Err(refused());
        };
        *slot = take_fragment(&fragment)?;
        return Ok(decoded);
    }
    if kind == "saveVaultSettings" {
        let token = BEARER_PATH
            .iter()
            .fold(command.clone(), |value, key| field(&value, key));
        if token.is_null() || token.is_undefined() || token == KEEP_STORED_BEARER {
            return decode(command);
        }
        let mut decoded = decode(&with_placeholder(command, &BEARER_PATH, &JsValue::NULL)?)?;
        let Command::SaveVaultSettings { settings } = &mut decoded else {
            return Err(refused());
        };
        let Some(byo) = settings.byo.as_mut() else {
            return Err(refused());
        };
        byo.access_token = ByoBearer::Set(take_bearer(&token)?);
        return Ok(decoded);
    }
    decode(command)
}

/// Encodes what a command answered.
pub fn encode_outcome(outcome: &CommandOutcome) -> Result<Ts<CommandOutcome>, JsError> {
    outcome
        .serialize(&SERIALIZER)
        .map(Ts::new_unchecked)
        .map_err(|_| JsError::new("the command outcome does not encode"))
}

fn decode(command: &JsValue) -> Result<Command, JsError> {
    serde_wasm_bindgen::from_value(command.clone()).map_err(|_| refused())
}

/// `value[key]`, or `undefined` where `value` is no object.
fn field(value: &JsValue, key: &str) -> JsValue {
    if !value.is_object() {
        return JsValue::UNDEFINED;
    }
    Reflect::get(value, &key.into()).unwrap_or(JsValue::UNDEFINED)
}

/// A shallow copy of `value` along `path`, with `placeholder` at its end. The
/// caller's object is left as it was.
fn with_placeholder(
    value: &JsValue,
    path: &[&str],
    placeholder: &JsValue,
) -> Result<JsValue, JsError> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(placeholder.clone());
    };
    if !value.is_object() {
        return Err(refused());
    }
    let copy = Object::assign(&Object::new(), value.unchecked_ref::<Object>());
    let inner = with_placeholder(&field(value, key), rest, placeholder)?;
    Reflect::set(&copy, &(*key).into(), &inner).map_err(|_| refused())?;
    Ok(copy.into())
}

/// An invite link's fragment, measured before it is copied into linear memory:
/// past the engine's own text bound it cannot be a link.
fn take_fragment(value: &JsValue) -> Result<Zeroizing<String>, JsError> {
    let text = value.dyn_ref::<JsString>().ok_or_else(refused)?;
    if text.length() as usize > MAX_FRAGMENT_TEXT_LEN {
        return Err(refused());
    }
    text.as_string().map(Zeroizing::new).ok_or_else(refused)
}

/// A provider bearer, from the buffer the host transferred. Bytes that are no
/// sendable bearer are wiped before the refusal returns.
fn take_bearer(value: &JsValue) -> Result<Zeroizing<String>, JsError> {
    let bytes = if let Some(buffer) = value.dyn_ref::<ArrayBuffer>() {
        Uint8Array::new(buffer).to_vec()
    } else if let Some(view) = value.dyn_ref::<Uint8Array>() {
        view.to_vec()
    } else {
        return Err(refused());
    };
    bearer_from_bytes(bytes).map_err(|error| JsError::new(&error.to_string()))
}
