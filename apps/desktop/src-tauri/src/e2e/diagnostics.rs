//! Pass-leg timings and slow requests on standard error, which the suite keeps
//! as the instance log. A line names legs, hosts, durations and outcome
//! classes only.

use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use cipherbox_desktop_seams::{SlowRequest, SlowRequestSink};
use cipherbox_engine::{PassTimingSink, PassTimings, TickCause};

/// A request this slow is reported: well inside the 30 s refresh deadline, so a
/// pass that crosses it names the requests that used it up.
pub const SLOW_REQUEST: Duration = Duration::from_secs(5);

/// Each pass's line on standard error.
pub fn pass_timings() -> PassTimingSink {
    Rc::new(|timings: &PassTimings| eprintln!("{}", pass_line(timings)))
}

/// Each slow request's line on standard error.
pub fn slow_requests() -> SlowRequestSink {
    Arc::new(|slow: &SlowRequest| eprintln!("{}", slow_line(slow)))
}

fn pass_line(timings: &PassTimings) -> String {
    let cause = match timings.cause {
        TickCause::Poll => "poll",
        TickCause::Manual => "manual",
    };
    let legs: Vec<String> = timings
        .legs
        .iter()
        .map(|(leg, millis)| format!("{leg} {millis}"))
        .collect();
    format!(
        "e2e: pass {cause} {} ms: {}",
        timings.total_ms(),
        legs.join(", ")
    )
}

fn slow_line(slow: &SlowRequest) -> String {
    format!(
        "e2e: slow {} {} {} ms {}",
        slow.kind, slow.host, slow.millis, slow.outcome
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_line_names_the_cause_the_total_and_each_leg() {
        let line = pass_line(&PassTimings {
            cause: TickCause::Manual,
            legs: vec![("root", 1_200), ("focus", 30_400), ("drain", 15)],
        });
        assert_eq!(
            line,
            "e2e: pass manual 31615 ms: root 1200, focus 30400, drain 15"
        );
    }

    #[test]
    fn a_slow_line_names_the_kind_the_host_and_the_outcome() {
        let line = slow_line(&SlowRequest {
            kind: "record-get",
            host: "delegated-ipfs.dev".to_owned(),
            millis: 30_002,
            outcome: "error".to_owned(),
        });
        assert_eq!(
            line,
            "e2e: slow record-get delegated-ipfs.dev 30002 ms error"
        );
    }
}
