//! The one decode of a facade command from its JS value, and the one encode of
//! what it answers, of each event and of each view. All are the engine's own types, typed for
//! TS by tsify (blueprint/web-client.md "WASM packaging and the type boundary").
//!
//! Serde buffers an internally tagged value whole before it picks the variant,
//! and frees that buffer unwiped when a later field refuses. So a command that
//! carries a secret decodes with a placeholder in the secret's place, and the
//! secret is taken into a zeroizing buffer only once the rest has decoded
//! (AGENTS.md rule 7). A refusal names no field value: a value can be a name
//! the member typed.

use cipherbox_engine::content::ByoBearer;
use cipherbox_engine::devices::MAX_IDENTITY_TOKEN_CHARS;
use cipherbox_engine::facade::{Command, CommandOutcome, Event};
use cipherbox_engine::grants::MAX_FRAGMENT_TEXT_LEN;
use cipherbox_engine::seams::check_bearer;
use cipherbox_engine::wire::{BIGINT_TAG, KEEP_STORED_BEARER};
use js_sys::{Array, ArrayBuffer, BigInt, JsString, Object, Reflect, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

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
        return decode_secret_text(command, "fragment", MAX_FRAGMENT_TEXT_LEN, |decoded| {
            match decoded {
                Command::ClaimInviteLink { fragment, .. } => Some(fragment),
                _ => None,
            }
        });
    }
    if kind == "registerDevice" {
        // A char is at most two UTF-16 units; the engine checks the char count.
        return decode_secret_text(
            command,
            "identityToken",
            2 * MAX_IDENTITY_TOKEN_CHARS,
            |decoded| match decoded {
                Command::RegisterDevice { identity_token, .. } => Some(identity_token),
                _ => None,
            },
        );
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

/// Encodes one event.
pub fn encode_event(event: &Event) -> Result<Ts<Event>, JsError> {
    event
        .serialize(&SERIALIZER)
        .map(Ts::new_unchecked)
        .map_err(|_| JsError::new("the event does not encode"))
}

/// Encodes one view, or one list of view rows.
pub fn encode_view<T: Serialize + ?Sized>(view: &T) -> Result<JsValue, JsError> {
    view.serialize(&SERIALIZER)
        .map_err(|_| JsError::new("the view does not encode"))
}

fn decode(command: &JsValue) -> Result<Command, JsError> {
    serde_wasm_bindgen::from_value(tag_bigints(command, 0)?).map_err(|_| refused())
}

/// How deep [`tag_bigints`] walks. The deepest command field,
/// `settings.byo.accessToken`, is at depth 3; a structured clone keeps cycles,
/// so the walk needs a bound.
const MAX_COMMAND_DEPTH: usize = 8;

/// A copy of `value` with each `bigint` in its plain objects replaced by a
/// [`BIGINT_TAG`] object, so the decode tells a `bigint` from a `number`.
/// Bytes and every other value pass as they are. A host object that already
/// has the tag key is refused, so no tag reaches the decode but this one. No
/// command field is an array, so an array is refused before serde buffers it
/// without a bound.
fn tag_bigints(value: &JsValue, depth: usize) -> Result<JsValue, JsError> {
    if value.is_bigint() {
        let decimal = value
            .unchecked_ref::<BigInt>()
            .to_string(10)
            .map_err(|_| refused())?;
        let tagged = Object::new();
        Reflect::set(&tagged, &BIGINT_TAG.into(), &decimal).map_err(|_| refused())?;
        return Ok(tagged.into());
    }
    if Array::is_array(value) {
        return Err(refused());
    }
    if !value.is_object() || value.is_instance_of::<ArrayBuffer>() || ArrayBuffer::is_view(value) {
        return Ok(value.clone());
    }
    if depth >= MAX_COMMAND_DEPTH {
        return Err(JsError::new("the command nests too deep"));
    }
    let object = value.unchecked_ref::<Object>();
    if Object::has_own(object, &BIGINT_TAG.into()) {
        return Err(refused());
    }
    let copy = Object::new();
    for key in Object::keys(object).iter() {
        let inner = tag_bigints(
            &Reflect::get(value, &key).map_err(|_| refused())?,
            depth + 1,
        )?;
        Reflect::set(&copy, &key, &inner).map_err(|_| refused())?;
    }
    Ok(copy.into())
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

/// Decodes `command` with the empty placeholder at `key`, then takes the text
/// at `key` into the zeroizing slot that `slot_of` names.
fn decode_secret_text(
    command: &JsValue,
    key: &str,
    max_units: usize,
    slot_of: fn(&mut Command) -> Option<&mut Zeroizing<String>>,
) -> Result<Command, JsError> {
    let secret = field(command, key);
    let mut decoded = decode(&with_placeholder(command, &[key], &"".into())?)?;
    let slot = slot_of(&mut decoded).ok_or_else(refused)?;
    *slot = take_text(&secret, max_units)?;
    Ok(decoded)
}

/// A secret text field, measured in UTF-16 units before it is copied into
/// linear memory: past `max_units` the engine would refuse it anyway.
fn take_text(value: &JsValue, max_units: usize) -> Result<Zeroizing<String>, JsError> {
    let text = value.dyn_ref::<JsString>().ok_or_else(refused)?;
    if text.length() as usize > max_units {
        return Err(refused());
    }
    text.as_string().map(Zeroizing::new).ok_or_else(refused)
}

/// A provider bearer, from the `ArrayBuffer` the host transferred. A view is
/// refused: the host moves and wipes a buffer alone, so a view would reach
/// here as a clone nobody scrubs. Bytes that are no sendable bearer are wiped
/// before the refusal returns; `String::from_utf8` reuses the allocation, so
/// the credential is never copied.
fn take_bearer(value: &JsValue) -> Result<Zeroizing<String>, JsError> {
    let buffer = value.dyn_ref::<ArrayBuffer>().ok_or_else(refused)?;
    let not_a_bearer = || JsError::new("accessToken must be a sendable bearer");
    let token = Zeroizing::new(String::from_utf8(Uint8Array::new(buffer).to_vec()).map_err(
        |error| {
            error.into_bytes().zeroize();
            not_a_bearer()
        },
    )?);
    check_bearer(&token).map_err(|_| not_a_bearer())?;
    Ok(token)
}
