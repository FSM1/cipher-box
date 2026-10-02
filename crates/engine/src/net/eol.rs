//! EOL policy and the RFC3339 timestamp codec (blueprint/engine.md
//! "Resolve/publish pipeline: TTL/EOL", "Liveness", #24 D1).
//!
//! Every published record carries a 90-day client-signed EOL
//! ([`cipherbox_core::ipns::DEFAULT_VALIDITY_DAYS`]) as an RFC3339 timestamp in
//! the signed `data.Validity` field. Core treats the timestamp as opaque bytes
//! and reads no clock (blueprint/core.md); the engine formats it from the
//! injected [`Scheduler`](crate::seams::Scheduler) clock here and compares a
//! resolved record's EOL against the same clock to drive the two liveness
//! decisions: **renewal** (below the threshold, republish at seq+1) and
//! **expiry** (a >EOL lapse, revive from the recovery endpoint). Determinism
//! law: every function here takes the instant as a [`UnixMillis`] argument.
//!
//! [`is_expired`] carries one verdict outside liveness — the vault settings
//! resolve's authority check (blueprint/engine.md "Vault settings load").
//! [`verify_record_outside_session`] serves a host that watches a name with no
//! session open.

use core::time::Duration;

use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::ipns::{DEFAULT_VALIDITY_DAYS, IpnsName, IpnsRecord};

use crate::net::MAX_RECORD_BYTES;
use crate::seams::UnixMillis;

/// What a signed IPNS record says about its own liveness, verified against the
/// name it was fetched under — the read an observer outside any session makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordReading {
    /// The record sequence number.
    pub sequence: u64,
    /// The signed RFC3339 EOL text.
    pub validity: String,
    /// The EOL as Unix millis; `None` where the text does not parse.
    pub valid_until: Option<u64>,
}

/// Verify `record` under `ipns_name` and read its sequence and EOL. The name's
/// key is the only trust anchor, so a record signed for another name fails.
/// Not a gated read: it adopts nothing, checks no floor, and does not compare the EOL with the time.
pub fn verify_record_outside_session(
    ipns_name: &str,
    record: &[u8],
) -> Result<RecordReading, CodecError> {
    if record.len() > MAX_RECORD_BYTES {
        return Err(Malformed::IpnsRecordMalformed.into());
    }
    let name = IpnsName::parse(ipns_name)?;
    let verified = IpnsRecord::unmarshal(record)?.verify(&name)?;
    let valid_until = parse_rfc3339(&verified.validity);
    let validity =
        String::from_utf8(verified.validity).map_err(|_| Malformed::IpnsRecordMalformed)?;
    Ok(RecordReading {
        sequence: verified.sequence,
        validity,
        valid_until,
    })
}

/// Seconds in one day.
const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// The sub-EOL renewal window: a name whose record has at or below this much
/// EOL remaining is republished at seq+1 through the CAS path (blueprint:
/// "below ~30 days remaining republishes the same CID at seq+1").
///
/// Designed-for cadence, not yet a frozen profile constant: like the sweep
/// cadence (blueprint/engine.md "Open edges"), it joins the sync timing
/// profile once the testing-strategy measurement process fixes it.
pub const EOL_RENEW_THRESHOLD: Duration = Duration::from_secs(30 * SECS_PER_DAY);

/// The full client-signed EOL window (90 days), as a [`Duration`]. Mirrors
/// core's [`DEFAULT_VALIDITY_DAYS`] — the policy the engine applies when it
/// stamps a fresh record.
pub const EOL_WINDOW: Duration = Duration::from_secs(DEFAULT_VALIDITY_DAYS * SECS_PER_DAY);

/// The RFC3339 EOL string for a record minted at `now`: `now + 90 days`,
/// formatted UTC at second precision (`YYYY-MM-DDTHH:MM:SSZ`). This is the exact
/// string handed to [`IpnsRecord::create_v2`](cipherbox_core::ipns::IpnsRecord::create_v2).
pub fn eol_from(now: UnixMillis) -> String {
    format_rfc3339(now.saturating_add(EOL_WINDOW))
}

/// The EOL a renewal walk signs at `now`: one day short of [`eol_from`], so a
/// real write another device signs at the same sequence carries the later EOL
/// (ADR 0061 D3 step 6).
pub fn renewal_eol_from(now: UnixMillis) -> String {
    format_rfc3339(
        now.saturating_add(EOL_WINDOW)
            .saturating_sub(Duration::from_secs(SECS_PER_DAY)),
    )
}

/// Whether the record `candidate` ranks above `held` at one sequence, each
/// given as its signed EOL and its signed `data`: the later EOL wins (ADR 0061
/// D3 step 7), then the higher `data` bytes (ADR 0066 D2), so every reader
/// takes one record whatever the endpoints serve. An EOL that does not parse
/// is never later than one that does.
pub fn ranks_above(candidate: (&[u8], &[u8]), held: (&[u8], &[u8])) -> bool {
    match parse_rfc3339(candidate.0).cmp(&parse_rfc3339(held.0)) {
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Equal => candidate.1 > held.1,
    }
}

/// Milliseconds of EOL remaining at `now` for a record whose signed
/// `Validity` bytes are `validity`. Negative once past the EOL; `None` when the
/// timestamp does not parse (a malformed record — the caller fails closed).
pub fn remaining_millis(now: UnixMillis, validity: &[u8]) -> Option<i64> {
    let eol = parse_rfc3339(validity)?;
    Some(i64::try_from(eol).unwrap_or(i64::MAX) - i64::try_from(now.0).unwrap_or(i64::MAX))
}

/// Whether the record has lapsed past its EOL at `now` (a revival trigger). An
/// unparseable EOL is treated as expired — fail-closed, the record cannot be
/// trusted to be live.
pub fn is_expired(now: UnixMillis, validity: &[u8]) -> bool {
    remaining_millis(now, validity).is_none_or(|remaining| remaining <= 0)
}

/// Whether the record is still live but within the renewal window at `now`
/// (a seq+1 republish trigger). A lapsed record is not a renewal case (that is
/// revival); an unparseable EOL is not renewed here either.
pub fn needs_renewal(now: UnixMillis, validity: &[u8], threshold: Duration) -> bool {
    match remaining_millis(now, validity) {
        Some(remaining) if remaining > 0 => {
            remaining <= i64::try_from(threshold.as_millis()).unwrap_or(i64::MAX)
        }
        _ => false,
    }
}

/// Format a UTC instant as `YYYY-MM-DDTHH:MM:SSZ` (second precision). Sub-second
/// millis are truncated — the EOL policy is day-scale, so second precision
/// round-trips exactly through [`parse_rfc3339`].
fn format_rfc3339(instant: UnixMillis) -> String {
    let total_secs = instant.0 / 1000;
    let days = (total_secs / SECS_PER_DAY) as i64;
    let sod = total_secs % SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse an RFC3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.frac]Z`) to Unix
/// milliseconds. Accepts an optional fractional-second part (millisecond
/// precision retained, finer digits truncated) and requires the trailing `Z`
/// (records are always minted UTC). `None` on any structural defect.
fn parse_rfc3339(bytes: &[u8]) -> Option<u64> {
    let text = core::str::from_utf8(bytes).ok()?;
    let (date, rest) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = parse_2(date_parts.next()?)?;
    let day: u32 = parse_2(date_parts.next()?)?;
    // Reject out-of-range calendar dates outright — an invalid day (e.g. Feb 30)
    // must fail closed, never silently normalize into the next month.
    if date_parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
    {
        return None;
    }

    let time = rest.strip_suffix('Z')?;
    // Split off an optional fractional-second part; keep at most 3 digits (ms).
    let (clock, frac) = match time.split_once('.') {
        Some((clock, frac)) => (clock, frac),
        None => (time, ""),
    };
    let mut clock_parts = clock.split(':');
    let hour: u64 = parse_2(clock_parts.next()?)?.into();
    let minute: u64 = parse_2(clock_parts.next()?)?.into();
    let second: u64 = parse_2(clock_parts.next()?)?.into();
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let millis_frac = fractional_millis(frac)?;

    let days = days_from_civil(year, month, day);
    let total_secs =
        days.checked_mul(SECS_PER_DAY as i64)? + (hour * 3600 + minute * 60 + second) as i64;
    let total_millis = total_secs.checked_mul(1000)? + millis_frac as i64;
    u64::try_from(total_millis).ok()
}

/// Parse an exactly-two-ASCII-digit field.
fn parse_2(field: &str) -> Option<u32> {
    if field.len() != 2 {
        return None;
    }
    field.parse().ok()
}

/// Millisecond value of a fractional-second string of ASCII digits (`""` → 0).
/// Only the first three digits contribute; the rest are truncated.
fn fractional_millis(frac: &str) -> Option<u32> {
    if !frac.is_empty() && !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut millis = 0u32;
    for i in 0..3 {
        millis = millis * 10 + frac.as_bytes().get(i).map_or(0, |b| u32::from(b - b'0'));
    }
    Some(millis)
}

/// Proleptic-Gregorian leap year.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in a validated `month` (1-12) of `year` — 29 for a leap February.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// Civil-date conversions (Howard Hinnant's algorithms): days since the Unix
// epoch ⇄ (year, month, day) in the proleptic Gregorian calendar, exact for the
// full u64-millis range the record EOL ever spans.

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The civil date `z` days after 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_round_trips_at_second_precision() {
        // A handful of instants across days, months, years, leap years.
        for millis in [
            0u64,
            1_000,
            86_400_000,
            1_700_000_000_000,
            1_800_000_000_000,
            4_102_444_800_000, // 2100-01-01
        ] {
            let s = format_rfc3339(UnixMillis(millis));
            let back = parse_rfc3339(s.as_bytes()).expect("our own format parses");
            assert_eq!(
                back,
                (millis / 1000) * 1000,
                "round-trip at second precision: {s}"
            );
        }
    }

    #[test]
    fn a_record_reads_its_sequence_and_eol_under_its_own_name_only() {
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        let signer = Ed25519Signer::from_seed([0x31; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let eol = eol_from(UnixMillis(1_700_000_000_000));
        let record = IpnsRecord::create_v2(&signer, b"/ipfs/bafyreading", 7, 1, &eol).marshal();

        assert_eq!(
            verify_record_outside_session(name.as_str(), &record),
            Ok(RecordReading {
                sequence: 7,
                validity: eol.clone(),
                valid_until: parse_rfc3339(eol.as_bytes()),
            })
        );

        let other =
            IpnsName::from_public_key(&Ed25519Signer::from_seed([0x32; 32]).verifying_key());
        assert_eq!(
            verify_record_outside_session(other.as_str(), &record).map_err(|error| error.class()),
            Err("trust"),
            "a record signed for another name is a trust violation"
        );
        assert_eq!(
            verify_record_outside_session(name.as_str(), &record[..record.len() - 1])
                .map_err(|error| error.class()),
            Err("malformed")
        );
    }

    /// A validly signed record of exactly `len` bytes. Each value byte adds two
    /// bytes, and a TTL of 24 adds one CBOR byte, so a search over both lands
    /// on any length. Length prefixes grow with the value, so the padding sits
    /// a few bytes under half the gap to the empty-value record.
    fn signed_record_of_len(
        signer: &cipherbox_core::suite::ed25519::Ed25519Signer,
        len: usize,
    ) -> Vec<u8> {
        let eol = eol_from(UnixMillis(1_700_000_000_000));
        let base = IpnsRecord::create_v2(signer, b"/ipfs/", 1, 1, &eol)
            .marshal()
            .len();
        let top = len.saturating_sub(base) / 2;
        (top.saturating_sub(8)..=top)
            .flat_map(|pad| [1u64, 24].map(move |ttl| (pad, ttl)))
            .map(|(pad, ttl)| {
                let value = [b"/ipfs/".as_slice(), &vec![b'a'; pad]].concat();
                IpnsRecord::create_v2(signer, &value, 1, ttl, &eol).marshal()
            })
            .find(|record| record.len() == len)
            .expect("some padding reaches the length")
    }

    #[test]
    fn a_record_past_the_fetch_cap_is_refused_before_the_decoder() {
        use cipherbox_core::suite::ed25519::Ed25519Signer;

        let signer = Ed25519Signer::from_seed([0x33; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());

        let at_cap = signed_record_of_len(&signer, MAX_RECORD_BYTES);
        assert_eq!(
            verify_record_outside_session(name.as_str(), &at_cap).map(|reading| reading.sequence),
            Ok(1),
            "a record at the cap reaches the decoder"
        );
        let over_cap = signed_record_of_len(&signer, MAX_RECORD_BYTES + 1);
        assert_eq!(
            verify_record_outside_session(name.as_str(), &over_cap),
            Err(Malformed::IpnsRecordMalformed.into())
        );
    }

    #[test]
    fn epoch_is_the_expected_string() {
        assert_eq!(format_rfc3339(UnixMillis(0)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2023-11-14T22:13:20Z
        assert_eq!(
            format_rfc3339(UnixMillis(1_700_000_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn parses_core_style_nanosecond_fraction() {
        // The form core's own tests emit — fractional seconds must be accepted.
        let millis = parse_rfc3339(b"2026-10-18T00:00:00.000000000Z").expect("parses");
        assert_eq!(format_rfc3339(UnixMillis(millis)), "2026-10-18T00:00:00Z");
    }

    #[test]
    fn eol_from_is_ninety_days_ahead() {
        let now = UnixMillis(1_700_000_000_000);
        let eol = eol_from(now);
        let eol_millis = parse_rfc3339(eol.as_bytes()).unwrap();
        assert_eq!(eol_millis - now.0, 90 * SECS_PER_DAY * 1000);
    }

    #[test]
    fn remaining_expiry_and_renewal_transitions() {
        let now = UnixMillis(1_700_000_000_000);
        let eol = eol_from(now); // now + 90 days
        let v = eol.as_bytes();

        // At mint time: ~90 days remaining, live, no renewal.
        assert!(remaining_millis(now, v).unwrap() > 0);
        assert!(!is_expired(now, v));
        assert!(!needs_renewal(now, v, EOL_RENEW_THRESHOLD));

        // 65 days in (25 days remaining): live, renewal due.
        let t65 = now.saturating_add(Duration::from_secs(65 * SECS_PER_DAY));
        assert!(!is_expired(t65, v));
        assert!(needs_renewal(t65, v, EOL_RENEW_THRESHOLD));

        // 91 days in: lapsed — expiry, never renewal.
        let t91 = now.saturating_add(Duration::from_secs(91 * SECS_PER_DAY));
        assert!(is_expired(t91, v));
        assert!(!needs_renewal(t91, v, EOL_RENEW_THRESHOLD));
    }

    #[test]
    fn unparseable_validity_is_expired_and_not_renewable() {
        let now = UnixMillis(1_700_000_000_000);
        assert!(remaining_millis(now, b"not-a-timestamp").is_none());
        assert!(is_expired(now, b"not-a-timestamp"));
        assert!(!needs_renewal(now, b"not-a-timestamp", EOL_RENEW_THRESHOLD));
    }

    #[test]
    fn parse_rejects_missing_zone_and_malformed_fields() {
        assert!(parse_rfc3339(b"2026-10-18T00:00:00").is_none(), "no Z");
        assert!(parse_rfc3339(b"2026-13-01T00:00:00Z").is_none(), "month 13");
        assert!(parse_rfc3339(b"2026-10-18T24:00:00Z").is_none(), "hour 24");
        assert!(
            parse_rfc3339(b"2026-1-1T0:0:0Z").is_none(),
            "unpadded fields"
        );
    }

    #[test]
    fn parse_rejects_out_of_range_calendar_dates() {
        // An invalid day for the month must fail closed, never normalize forward.
        assert!(parse_rfc3339(b"2026-02-30T00:00:00Z").is_none(), "Feb 30");
        assert!(
            parse_rfc3339(b"2025-02-29T00:00:00Z").is_none(),
            "Feb 29 in a non-leap year"
        );
        assert!(parse_rfc3339(b"2026-04-31T00:00:00Z").is_none(), "Apr 31");
        assert!(parse_rfc3339(b"2026-01-32T00:00:00Z").is_none(), "Jan 32");
        assert!(parse_rfc3339(b"2026-01-00T00:00:00Z").is_none(), "day 00");
        // Genuine leap-day and month-length boundaries still parse.
        assert!(
            parse_rfc3339(b"2024-02-29T00:00:00Z").is_some(),
            "Feb 29 in a leap year"
        );
        assert!(parse_rfc3339(b"2026-04-30T00:00:00Z").is_some(), "Apr 30");
        assert!(
            parse_rfc3339(b"2000-02-29T00:00:00Z").is_some(),
            "Feb 29 2000"
        );
        assert!(
            parse_rfc3339(b"1900-02-29T00:00:00Z").is_none(),
            "1900 is not a leap year (century, not 400)"
        );
    }

    /// At one EOL the higher signed `data` ranks above; a later EOL ranks
    /// above whatever its `data`; an EOL that does not parse ranks below one
    /// that does; and a record never ranks above itself.
    #[test]
    fn ranks_above_takes_the_later_eol_then_the_higher_data() {
        let (eol, later) = (b"2099-01-01T00:00:00Z", b"2099-01-02T00:00:00Z");
        assert!(ranks_above((eol, b"b"), (eol, b"a")));
        assert!(!ranks_above((eol, b"a"), (eol, b"b")));
        assert!(ranks_above((later, b"a"), (eol, b"b")));
        assert!(!ranks_above((b"not-a-time", b"z"), (eol, b"a")));
        assert!(!ranks_above((eol, b"a"), (eol, b"a")));
    }
}
