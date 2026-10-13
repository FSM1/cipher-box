//! Pass-leg timings and slow requests on standard error, which the suite keeps
//! as the instance log. Each line starts with the UTC wall-clock time, so a
//! line matches the harness check that failed beside it.

use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use cipherbox_desktop_seams::{SlowRequest, SlowRequestSink, TokioScheduler};
use cipherbox_engine::seams::Scheduler;
use cipherbox_engine::{PassEvent, PassTimingSink, TickCause};

/// A request this slow is reported: well inside the 30 s refresh deadline, so a
/// pass that crosses it names the requests that used it up.
pub const SLOW_REQUEST: Duration = Duration::from_secs(5);

/// Each pass event's line on standard error.
pub fn pass_timings() -> PassTimingSink {
    Rc::new(|event: &PassEvent| eprintln!("{}", pass_line(&wall_clock(), event)))
}

/// Each slow request's line on standard error.
pub fn slow_requests() -> SlowRequestSink {
    Arc::new(|slow: &SlowRequest| eprintln!("{}", slow_line(&wall_clock(), slow)))
}

fn pass_line(at: &str, event: &PassEvent) -> String {
    match event {
        PassEvent::Started { pass, cause } => {
            let cause = match cause {
                TickCause::Poll => "poll",
                TickCause::Manual => "manual",
            };
            format!("e2e: {at} pass {pass} {cause} started")
        }
        PassEvent::LegEnded {
            pass,
            leg,
            millis,
            next,
        } => {
            let then = next.map_or_else(|| "ended".to_owned(), |next| format!("next {next}"));
            format!("e2e: {at} pass {pass} {leg} {millis} ms, {then}")
        }
    }
}

fn slow_line(at: &str, slow: &SlowRequest) -> String {
    format!(
        "e2e: {at} slow {} {} {} ms {}",
        slow.kind, slow.host, slow.millis, slow.outcome
    )
}

/// Now, as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn wall_clock() -> String {
    utc(TokioScheduler::new().now().0)
}

/// `millis` past the Unix epoch, in UTC. The date is the days-to-civil
/// conversion of the proleptic Gregorian calendar.
fn utc(millis: u64) -> String {
    let days = millis / 86_400_000;
    let of_day = millis % 86_400_000;
    let era_days = days + 719_468;
    let era = era_days / 146_097;
    let day_of_era = era_days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1_000 % 60,
        of_day % 1_000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: &str = "2026-10-12T14:17:11.042Z";

    #[test]
    fn a_pass_line_names_the_pass_and_the_leg_it_moves_to() {
        assert_eq!(
            pass_line(
                AT,
                &PassEvent::Started {
                    pass: 7,
                    cause: TickCause::Manual
                }
            ),
            "e2e: 2026-10-12T14:17:11.042Z pass 7 manual started"
        );
        assert_eq!(
            pass_line(
                AT,
                &PassEvent::LegEnded {
                    pass: 7,
                    leg: "root",
                    millis: 30_400,
                    next: Some("scope-walk")
                }
            ),
            "e2e: 2026-10-12T14:17:11.042Z pass 7 root 30400 ms, next scope-walk"
        );
        assert_eq!(
            pass_line(
                AT,
                &PassEvent::LegEnded {
                    pass: 7,
                    leg: "received-shares",
                    millis: 15,
                    next: None
                }
            ),
            "e2e: 2026-10-12T14:17:11.042Z pass 7 received-shares 15 ms, ended"
        );
    }

    #[test]
    fn a_slow_line_names_the_kind_the_host_and_the_outcome() {
        let line = slow_line(
            AT,
            &SlowRequest {
                kind: "record-get",
                host: "delegated-ipfs.dev".to_owned(),
                millis: 30_002,
                outcome: "error".to_owned(),
            },
        );
        assert_eq!(
            line,
            "e2e: 2026-10-12T14:17:11.042Z slow record-get delegated-ipfs.dev 30002 ms error"
        );
    }

    #[test]
    fn the_wall_clock_is_utc_with_milliseconds() {
        assert_eq!(utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(utc(1_791_814_631_042), "2026-10-12T14:17:11.042Z");
        assert_eq!(utc(1_798_761_599_999), "2026-12-31T23:59:59.999Z");
    }
}
