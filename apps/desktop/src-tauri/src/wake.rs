//! The two host moments that force a sync pass beside the tray's "Sync Now": a
//! network reconnect and a wake from sleep (ADR 0044 D1). Each forces one pass,
//! on the moment only and never at launch, as the web host's refresh on wake
//! does.
//!
//! One sampler covers all three platforms. A sleep stops the clock a thread
//! sleeps against but not the wall clock, so a sample that lands long after
//! the last one says the host slept. A reconnect is a routable address the
//! last sample did not hold.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Manager};

use crate::engine::EngineHost;

/// How often the host is sampled — the most a forced pass trails its moment.
const PERIOD: Duration = Duration::from_secs(5);

/// A wall-clock gap between two samples past this is a sleep. A shorter stall
/// is scheduling noise.
const RESUME_GAP: Duration = Duration::from_secs(30);

/// A moment that forces a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    Reconnected,
    Resumed,
}

/// What the host looked like at one instant.
struct Sample {
    at: SystemTime,
    addresses: BTreeSet<IpAddr>,
}

impl Sample {
    fn now() -> Self {
        Self {
            at: SystemTime::now(),
            addresses: routable_addresses(),
        }
    }
}

/// Addresses that can reach a network beyond this host. An error reads as none:
/// the cost is one extra pass when the list reads again.
fn routable_addresses() -> BTreeSet<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces
                .iter()
                .filter(|interface| !interface.is_loopback() && !interface.is_link_local())
                .map(|interface| interface.ip())
                .collect()
        })
        .unwrap_or_default()
}

/// The moments between two consecutive samples. A clock set back is no sleep.
fn moments(last: &Sample, next: &Sample) -> impl Iterator<Item = Wake> {
    let resumed = next
        .at
        .duration_since(last.at)
        .is_ok_and(|gap| gap > RESUME_GAP);
    let reconnected = !next.addresses.is_subset(&last.addresses);
    [
        resumed.then_some(Wake::Resumed),
        reconnected.then_some(Wake::Reconnected),
    ]
    .into_iter()
    .flatten()
}

/// Forces one pass per moment in `samples`. The first sample is the baseline.
fn watch(samples: impl IntoIterator<Item = Sample>, mut force_pass: impl FnMut(Wake)) {
    let mut samples = samples.into_iter();
    let Some(mut last) = samples.next() else {
        return;
    };
    for next in samples {
        moments(&last, &next).for_each(&mut force_pass);
        last = next;
    }
}

/// Samples the host for the life of the app. A moment with no session live
/// forces nothing.
pub fn spawn(app: AppHandle) -> std::io::Result<()> {
    thread::Builder::new()
        .name("cipherbox-wake".to_owned())
        .spawn(move || {
            let samples = std::iter::once_with(Sample::now).chain(std::iter::repeat_with(|| {
                thread::sleep(PERIOD);
                Sample::now()
            }));
            let host = app.state::<EngineHost>();
            watch(samples, |_| host.force_pass());
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCH: Duration = Duration::from_secs(1_800_000_000);

    fn sample(seconds: u64, addresses: &[&str]) -> Sample {
        Sample {
            at: SystemTime::UNIX_EPOCH + LAUNCH + Duration::from_secs(seconds),
            addresses: addresses
                .iter()
                .map(|address| address.parse().expect("an address"))
                .collect(),
        }
    }

    fn forced(samples: Vec<Sample>) -> Vec<Wake> {
        let mut forced = Vec::new();
        watch(samples, |wake| forced.push(wake));
        forced
    }

    #[test]
    fn a_launch_and_a_steady_host_force_no_pass() {
        let wifi = ["192.168.1.20"];
        assert_eq!(
            forced(vec![sample(0, &wifi), sample(5, &wifi), sample(10, &wifi)]),
            []
        );
        assert_eq!(forced(vec![sample(0, &wifi)]), []);
    }

    #[test]
    fn a_network_reconnect_forces_one_pass() {
        let wifi = ["192.168.1.20", "2001:db8::20"];
        assert_eq!(
            forced(vec![
                sample(0, &wifi),
                sample(5, &[]),
                sample(10, &wifi),
                sample(15, &wifi),
            ]),
            [Wake::Reconnected]
        );
    }

    /// A network that goes is not a moment a pass can land in; only its
    /// return is.
    #[test]
    fn losing_the_network_forces_no_pass() {
        assert_eq!(
            forced(vec![sample(0, &["192.168.1.20"]), sample(5, &[])]),
            []
        );
    }

    /// A tunnel or a container bridge that stays up leaves the host never
    /// offline, and the network it rejoins is still a reconnect.
    #[test]
    fn a_new_network_beside_one_that_stayed_up_is_a_reconnect() {
        assert_eq!(
            forced(vec![
                sample(0, &["100.64.0.7", "192.168.1.20"]),
                sample(5, &["100.64.0.7"]),
                sample(10, &["100.64.0.7", "10.0.0.31"]),
            ]),
            [Wake::Reconnected]
        );
    }

    #[test]
    fn a_wake_from_sleep_forces_one_pass() {
        let wifi = ["192.168.1.20"];
        assert_eq!(
            forced(vec![
                sample(0, &wifi),
                sample(3_600, &wifi),
                sample(3_605, &wifi),
            ]),
            [Wake::Resumed]
        );
    }

    #[test]
    fn a_short_stall_is_not_a_sleep() {
        let wifi = ["192.168.1.20"];
        assert_eq!(forced(vec![sample(0, &wifi), sample(30, &wifi)]), []);
    }

    #[test]
    fn a_clock_set_back_is_not_a_sleep() {
        let wifi = ["192.168.1.20"];
        assert_eq!(forced(vec![sample(3_600, &wifi), sample(0, &wifi)]), []);
    }

    /// A sleep that also changed the network is two moments, each forcing its
    /// pass; the engine answers both with one (ADR 0044 D1).
    #[test]
    fn a_wake_onto_a_new_network_is_both_moments() {
        assert_eq!(
            forced(vec![
                sample(0, &["192.168.1.20"]),
                sample(3_600, &["10.0.0.31"])
            ]),
            [Wake::Resumed, Wake::Reconnected]
        );
    }
}
