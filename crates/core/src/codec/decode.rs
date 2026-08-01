//! The strict decoder. Accepts deterministic-profile CBOR only; every other
//! well-formed or ill-formed input rejects fail-closed with the named check
//! (blueprint/core.md "Wire format": one strictness policy, everywhere).

use super::MAX_DEPTH;
use super::encode::{
    MAJOR_ARRAY, MAJOR_BYTES, MAJOR_MAP, MAJOR_NEGATIVE, MAJOR_SIMPLE, MAJOR_TEXT, MAJOR_UNSIGNED,
    SIMPLE_FALSE, SIMPLE_NULL, SIMPLE_TRUE,
};
use super::value::{Map, Value, canonical_key_cmp};
use crate::error::{CodecError, Malformed, TrustViolation};

/// Decode exactly one deterministic-profile item spanning the whole input.
pub fn decode(bytes: &[u8]) -> Result<Value, CodecError> {
    let mut d = Decoder::new(bytes);
    let mut value = d.read_value(0)?;
    let guard = InFlight(&mut value);
    d.expect_end()?;
    core::mem::forget(guard);
    Ok(value)
}

/// Wipes what a decode has already read when a later read rejects. Every
/// decoded buffer is a verbatim copy of what the input carried — inline content
/// keys and seed material on the seal surfaces — and the decoder owns it until
/// it returns, below any guard a caller can install (blueprint/core.md "Crypto
/// suite": key material lives only in zeroizing owners). Borrows rather than
/// owns, so forgetting it disarms it and leaks nothing.
struct InFlight<'a, T: Scrub>(&'a mut T);

/// What an [`InFlight`] guard wipes.
trait Scrub {
    fn scrub(&mut self);
}

impl Scrub for Value {
    fn scrub(&mut self) {
        self.zeroize_bytes();
    }
}

impl Scrub for Vec<Value> {
    fn scrub(&mut self) {
        for value in self {
            value.zeroize_bytes();
        }
    }
}

impl<T: Scrub> Drop for InFlight<'_, T> {
    fn drop(&mut self) {
        self.0.scrub();
    }
}

pub(super) struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

/// A parsed head: major type, argument value, the raw additional-info bits,
/// and where the item started. For major 7 the additional info is a selector
/// (simple value or float width), not an integer argument — dispatch on `ai`.
pub(super) struct Head {
    pub major: u8,
    pub arg: u64,
    pub ai: u8,
    pub offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    pub(super) fn expect_end(&self) -> Result<(), CodecError> {
        if self.pos != self.input.len() {
            return Err(Malformed::TrailingBytes { offset: self.pos }.into());
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let start = self.pos;
        let end = start
            .checked_add(n)
            .filter(|&e| e <= self.input.len())
            .ok_or(Malformed::Truncated { offset: start })?;
        self.pos = end;
        Ok(&self.input[start..end])
    }

    fn take_byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// Read one head, enforcing shortest-form arguments and rejecting every
    /// profile-forbidden shape (tags, indefinite lengths, reserved ai).
    pub(super) fn read_head(&mut self) -> Result<Head, CodecError> {
        let offset = self.pos;
        let initial = self.take_byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;

        // Tags reject on the initial byte, before argument decoding: the
        // profile admits none, whatever their number's form.
        if major == 6 {
            return Err(Malformed::TagForbidden { offset }.into());
        }

        let arg = match self.read_arg(ai)? {
            Some(arg) => arg,
            None => {
                // ai 28–30 reserved everywhere; 31 is indefinite/break,
                // legal in no deterministic encoding.
                return Err(match (major, ai) {
                    (MAJOR_BYTES | MAJOR_TEXT | MAJOR_ARRAY | MAJOR_MAP, 31) => {
                        TrustViolation::IndefiniteLength { offset }.into()
                    }
                    (MAJOR_SIMPLE, 31) => CodecError::from(Malformed::UnexpectedBreak { offset }),
                    _ => Malformed::ReservedAdditionalInfo { offset }.into(),
                });
            }
        };

        // Shortest-form enforcement (RFC 8949 §4.2.1). Major 7's ai is a
        // simple-value selector, not an integer argument — handled by caller.
        if major != MAJOR_SIMPLE {
            let minimal = ai < 24
                || match ai {
                    24 => arg >= 24,
                    25 => arg > 0xff,
                    26 => arg > 0xffff,
                    27 => arg > 0xffff_ffff,
                    _ => unreachable!(),
                };
            if !minimal {
                return Err(match major {
                    MAJOR_UNSIGNED | MAJOR_NEGATIVE => {
                        TrustViolation::NonCanonicalUint { offset }.into()
                    }
                    _ => CodecError::from(TrustViolation::NonCanonicalLength { offset }),
                });
            }
        }

        Ok(Head {
            major,
            arg,
            ai,
            offset,
        })
    }

    /// The argument for an additional-info value; `None` for 28–31.
    fn read_arg(&mut self, ai: u8) -> Result<Option<u64>, CodecError> {
        Ok(match ai {
            0..=23 => Some(u64::from(ai)),
            24 => Some(u64::from(self.take_byte()?)),
            25 => Some(u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("len 2"),
            ))),
            26 => Some(u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("len 4"),
            ))),
            27 => Some(u64::from_be_bytes(self.take(8)?.try_into().expect("len 8"))),
            _ => None,
        })
    }

    fn take_len(&mut self, arg: u64, offset: usize) -> Result<&'a [u8], CodecError> {
        let remaining = (self.input.len() - self.pos) as u64;
        if arg > remaining {
            return Err(Malformed::Truncated { offset }.into());
        }
        // arg <= remaining <= usize::MAX (a slice length), so the cast is
        // lossless on every target, including 32-bit wasm.
        self.take(arg as usize)
    }

    pub(super) fn read_value(&mut self, depth: usize) -> Result<Value, CodecError> {
        if depth >= MAX_DEPTH {
            return Err(Malformed::DepthExceeded { offset: self.pos }.into());
        }
        let head = self.read_head()?;
        match head.major {
            MAJOR_UNSIGNED => Ok(Value::Unsigned(head.arg)),
            MAJOR_NEGATIVE => Ok(Value::Negative(head.arg)),
            MAJOR_BYTES => Ok(Value::Bytes(self.take_len(head.arg, head.offset)?.to_vec())),
            MAJOR_TEXT => {
                let raw = self.take_len(head.arg, head.offset)?;
                let text = core::str::from_utf8(raw).map_err(|_| Malformed::InvalidUtf8 {
                    offset: head.offset,
                })?;
                Ok(Value::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                let mut items = Vec::new();
                let guard = InFlight(&mut items);
                for _ in 0..head.arg {
                    guard.0.push(self.read_value(depth + 1)?);
                }
                core::mem::forget(guard);
                Ok(Value::Array(items))
            }
            MAJOR_MAP => {
                // Keys are field names, never secret, so they sit outside the
                // guard and carry the ascending-order check.
                let mut keys: Vec<String> = Vec::new();
                let mut values = Vec::new();
                let guard = InFlight(&mut values);
                for _ in 0..head.arg {
                    let key = self.read_map_key(keys.last().map(String::as_str))?;
                    let value = self.read_value(depth + 1)?;
                    keys.push(key);
                    guard.0.push(value);
                }
                core::mem::forget(guard);
                // Order and uniqueness were enforced entry-by-entry, so this
                // rebuild cannot reorder or drop anything.
                Ok(Value::Map(keys.into_iter().zip(values).collect::<Map>()))
            }
            // Dispatch on the additional info, never the argument: ai 25–27
            // carry float bit patterns in `arg`, which would otherwise alias
            // the simple-value space (e.g. a half float 0x0014 vs `false`).
            MAJOR_SIMPLE => match head.ai {
                SIMPLE_FALSE => Ok(Value::Bool(false)),
                SIMPLE_TRUE => Ok(Value::Bool(true)),
                SIMPLE_NULL => Ok(Value::Null),
                25..=27 => Err(Malformed::FloatForbidden {
                    offset: head.offset,
                }
                .into()),
                _ => Err(Malformed::SimpleValueForbidden {
                    offset: head.offset,
                }
                .into()),
            },
            _ => unreachable!("major 6 rejected in read_head"),
        }
    }

    /// A map key: text-typed, strictly ascending vs. the previous key.
    pub(super) fn read_map_key(&mut self, prev: Option<&str>) -> Result<String, CodecError> {
        let offset = self.pos;
        let head = self.read_head()?;
        if head.major != MAJOR_TEXT {
            return Err(Malformed::InvalidMapKeyType { offset }.into());
        }
        let raw = self.take_len(head.arg, head.offset)?;
        let key = core::str::from_utf8(raw).map_err(|_| Malformed::InvalidUtf8 {
            offset: head.offset,
        })?;
        if let Some(prev) = prev {
            match canonical_key_cmp(prev, key) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(TrustViolation::DuplicateMapKey {
                        offset,
                        key: key.to_owned(),
                    }
                    .into());
                }
                core::cmp::Ordering::Greater => {
                    return Err(TrustViolation::UnsortedMapKeys { offset }.into());
                }
            }
        }
        Ok(key.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard standing between a mid-item reject and a heap holding every
    /// secret the decode had already lifted out of its input.
    #[test]
    fn the_in_flight_guard_wipes_what_it_guards() {
        let mut items = vec![Value::Bytes(vec![0xAB; 32]), Value::Unsigned(7)];
        drop(InFlight(&mut items));
        assert_eq!(items[0], Value::Bytes(Vec::new()));
        assert_eq!(items[1], Value::Unsigned(7), "shape and scalars kept");

        let mut value = Value::Array(vec![Value::Text("secret-file.txt".into())]);
        drop(InFlight(&mut value));
        assert_eq!(
            value.as_array().unwrap()[0],
            Value::Text(String::new()),
            "the whole-tree guard wipes nested buffers too"
        );
    }

    /// The map arm accumulates keys and values apart; the ordering checks still
    /// see the previous key.
    #[test]
    fn map_key_order_checks_survive_the_split_accumulators() {
        // {"b": 1, "a": 2}
        let unsorted = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert_eq!(decode(&unsorted).unwrap_err().check(), "unsorted-map-keys");
        // {"a": 1, "a": 2}
        let duplicate = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert_eq!(decode(&duplicate).unwrap_err().check(), "duplicate-map-key");
    }
}
