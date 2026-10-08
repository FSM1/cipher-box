//! The one decode of a facade command from its JS value, and the one encode of
//! what it answers, of each event and of each view. All are the engine's own
//! types, typed for TS by tsify (blueprint/web-client.md "WASM packaging and
//! the type boundary").
//!
//! Serde buffers an internally tagged value whole before it picks the variant,
//! and frees that buffer unwiped when a later field refuses. So a command that
//! carries a secret decodes with a placeholder in the secret's place, and the
//! secret is taken into a zeroizing buffer only once the rest has decoded
//! (AGENTS.md rule 7). A refusal names no field value: a value can be a name
//! the member typed.

use crate::read::Read;
use crate::rendezvous::{DeviceRendezvousStep, Secret};
use cipherbox_engine::content::ByoBearer;
use cipherbox_engine::devices::MAX_IDENTITY_TOKEN_CHARS;
use cipherbox_engine::facade::{Command, CommandOutcome, Event, WriteTarget};
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
    let command = &bounded_copy(command, true, refused)?;
    let kind = field(command, "kind");
    if kind == "claimInviteLink" {
        return decode_secret_text(
            command,
            "fragment",
            MAX_FRAGMENT_TEXT_LEN,
            decode,
            |decoded| match decoded {
                Command::ClaimInviteLink { fragment, .. } => Some(fragment),
                _ => None,
            },
        );
    }
    if kind == "registerDevice" {
        // A char is at most two UTF-16 units; the engine checks the char count.
        return decode_secret_text(
            command,
            "identityToken",
            2 * MAX_IDENTITY_TOKEN_CHARS,
            decode,
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

/// Decodes one read. Refuses an unknown `kind`, an unknown field, and a field
/// of the wrong type. The two secrets a read carries, an invite fragment and a
/// rendezvous step's scalars, reach linear memory only in zeroizing buffers.
pub fn decode_read(read: &JsValue) -> Result<Read, JsError> {
    let read = &bounded_copy(read, false, read_refused)?;
    match field(read, "kind").as_string().as_deref() {
        Some("invitePreview") => decode_secret_text(
            read,
            "fragment",
            MAX_FRAGMENT_TEXT_LEN,
            decode_plain_read,
            |decoded| match decoded {
                Read::InvitePreview { fragment } => Some(fragment),
                _ => None,
            },
        )
        .map_err(|_| read_refused()),
        Some("deviceRendezvous") => {
            let step = field(read, "step");
            if step.is_undefined() || Object::keys(read.unchecked_ref::<Object>()).length() != 2 {
                return Err(read_refused());
            }
            decode_rendezvous_step(&step).map(|step| Read::DeviceRendezvous { step })
        }
        _ => decode_plain_read(read),
    }
}

fn decode_plain_read(read: &JsValue) -> Result<Read, JsError> {
    serde_wasm_bindgen::from_value(read.clone()).map_err(|_| read_refused())
}

fn read_refused() -> JsError {
    JsError::new("the read does not decode")
}

/// Decodes where a streaming write lands. Refuses a target that names both a
/// new file and a version, an unknown field, and a field of the wrong type.
pub fn decode_write_target(target: JsValue) -> Result<WriteTarget, JsError> {
    let refused = || JsError::new("the write target does not decode");
    serde_wasm_bindgen::from_value(bounded_copy(&target, false, refused)?).map_err(|_| refused())
}

/// Decodes one device-rendezvous step; its secrets go through
/// [`take_rendezvous_secrets`]. Refuses an unknown `kind`, an unknown field,
/// and a field of the wrong type.
pub fn decode_rendezvous_step(step: &JsValue) -> Result<DeviceRendezvousStep, JsError> {
    if !step.is_object() {
        return Err(rendezvous_refused());
    }
    let step = &bounded_copy(step, false, rendezvous_refused)?;
    // An absent secret stays absent, so serde refuses it as a missing field.
    let placeheld: Vec<String> = Object::keys(step.unchecked_ref::<Object>())
        .iter()
        .filter_map(|key| key.as_string())
        .filter(|key| is_bytes(&field(step, key)))
        .collect();
    let value = placeheld
        .iter()
        .try_fold(step.clone(), |value, key| {
            with_placeholder(&value, &[key], &Uint8Array::new_with_length(0).into())
        })
        .map_err(|_| rendezvous_refused())?;
    let mut decoded: DeviceRendezvousStep =
        serde_wasm_bindgen::from_value(value).map_err(|_| rendezvous_refused())?;
    take_rendezvous_secrets(step, &placeheld, decoded.secrets_mut())?;
    Ok(decoded)
}

/// Takes the secret at each of `placeheld` from `step` into its slot. Refuses
/// unless the slots name exactly the placeheld fields, and refuses an empty
/// secret: either would leave a slot that holds the placeholder.
pub fn take_rendezvous_secrets(
    step: &JsValue,
    placeheld: &[String],
    slots: Vec<(&str, &mut Secret)>,
) -> Result<(), JsError> {
    let named = |key: &String| slots.iter().any(|(slot, _)| slot == key);
    if slots.len() != placeheld.len() || !placeheld.iter().all(named) {
        return Err(rendezvous_refused());
    }
    for (key, slot) in slots {
        let bytes = field(step, key);
        let bytes = bytes
            .dyn_ref::<Uint8Array>()
            .filter(|bytes| bytes.length() > 0)
            .ok_or_else(rendezvous_refused)?;
        *slot = Zeroizing::new(bytes.to_vec());
    }
    Ok(())
}

fn rendezvous_refused() -> JsError {
    JsError::new("the rendezvous step does not decode")
}

fn is_bytes(value: &JsValue) -> bool {
    value.is_instance_of::<ArrayBuffer>() || ArrayBuffer::is_view(value)
}

/// Encodes one view, or one list of view rows.
pub fn encode_view<T: Serialize + ?Sized>(view: &T) -> Result<JsValue, JsError> {
    view.serialize(&SERIALIZER)
        .map_err(|_| JsError::new("the view does not encode"))
}

fn decode(command: &JsValue) -> Result<Command, JsError> {
    serde_wasm_bindgen::from_value(command.clone()).map_err(|_| refused())
}

/// The bounds on a value the boundary decodes, which come over a port from
/// another tab. A structured clone keeps cycles and shared references, so
/// depth, width and total work each need a cap. The widest legitimate objects,
/// a `respondToApproval` command and the `approve` and `openFactor` rendezvous
/// steps, have 7 keys; the deepest field, `settings.byo.accessToken`, is at
/// depth 3; a `saveVaultSettings` command, the largest value, makes 10 visits.
/// Each cap leaves a margin over that.
const MAX_VALUE_DEPTH: usize = 8;
/// Keys in one object; see [`MAX_VALUE_DEPTH`].
const MAX_VALUE_KEYS: u32 = 16;
/// Values the walk visits in all, shared ones each time; see [`MAX_VALUE_DEPTH`].
const MAX_VALUE_VISITS: usize = 64;

/// A copy of `value` that serde decodes in its place, built in one bounded
/// walk that reads each value once. Refuses a value past a cap, an array, an
/// own `__proto__` key, and an object whose prototype is not
/// `Object.prototype`. A `Map` or a `Set` hides its entries from the caps. A
/// null-prototype object does not, but no legitimate value holds one. With
/// `tag_bigints`, each `bigint` becomes a [`BIGINT_TAG`] object, so the command
/// decode tells a `bigint` from a `number`; an object that already has the tag
/// key is refused, so no tag reaches the decode but this one. Each decode takes
/// this copy before any other: a copy made with a set, as [`with_placeholder`]
/// makes, drops an own `__proto__` key before the walk can see it.
fn bounded_copy(
    value: &JsValue,
    tag_bigints: bool,
    refusal: fn() -> JsError,
) -> Result<JsValue, JsError> {
    let plain = Object::get_prototype_of(&Object::new());
    let mut walk = BoundedWalk {
        visits: 0,
        tag_bigints,
        plain,
    };
    walk.copy(value, 0).map_err(|()| refusal())
}

struct BoundedWalk {
    visits: usize,
    tag_bigints: bool,
    /// `Object.prototype`.
    plain: Object,
}

impl BoundedWalk {
    fn copy(&mut self, value: &JsValue, depth: usize) -> Result<JsValue, ()> {
        self.visits += 1;
        if self.visits > MAX_VALUE_VISITS || Array::is_array(value) {
            return Err(());
        }
        if self.tag_bigints && value.is_bigint() {
            let decimal = value
                .unchecked_ref::<BigInt>()
                .to_string(10)
                .map_err(|_| ())?;
            let tagged = Object::new();
            Reflect::set(&tagged, &BIGINT_TAG.into(), &decimal).map_err(|_| ())?;
            return Ok(tagged.into());
        }
        if !value.is_object() || is_bytes(value) {
            return Ok(value.clone());
        }
        if depth >= MAX_VALUE_DEPTH || !Object::is(&Object::get_prototype_of(value), &self.plain) {
            return Err(());
        }
        let object = value.unchecked_ref::<Object>();
        if Object::has_own(object, &BIGINT_TAG.into()) {
            return Err(());
        }
        let keys = Object::keys(object);
        if keys.length() > MAX_VALUE_KEYS {
            return Err(());
        }
        let copy = Object::new();
        for key in keys.iter() {
            // A set of `__proto__` on the copy would replace its prototype
            // and drop the field the decode must refuse.
            if key == "__proto__" {
                return Err(());
            }
            let inner = self.copy(&Reflect::get(value, &key).map_err(|_| ())?, depth + 1)?;
            Reflect::set(&copy, &key, &inner).map_err(|_| ())?;
        }
        Ok(copy.into())
    }
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

/// Decodes `value` with the empty placeholder at `key`, then takes the text
/// at `key` into the zeroizing slot that `slot_of` names.
fn decode_secret_text<T>(
    value: &JsValue,
    key: &str,
    max_units: usize,
    decode: fn(&JsValue) -> Result<T, JsError>,
    slot_of: fn(&mut T) -> Option<&mut Zeroizing<String>>,
) -> Result<T, JsError> {
    let secret = field(value, key);
    let mut decoded = decode(&with_placeholder(value, &[key], &"".into())?)?;
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
