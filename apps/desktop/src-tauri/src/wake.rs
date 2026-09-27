//! The two host moments that force a sync pass beside the tray's "Sync Now": a
//! network reconnect and a wake from sleep (ADR 0044 D1). A moment forces one
//! pass, on the moment only and never at launch, as the web host's refresh on
//! wake does.
//!
//! One sampler covers all three platforms. A sleep stops the clock a thread
//! sleeps against but not the wall clock, so a sample that lands long after
//! the last one says the host slept. A reconnect is a network the last sample
//! did not reach.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::thread;
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Manager};

use crate::engine::EngineHost;

/// How often the host is sampled — the most a forced pass trails its moment.
const PERIOD: Duration = Duration::from_secs(5);

/// A wall-clock gap between two samples past this is a sleep. A shorter stall
/// is scheduling noise.
const RESUME_GAP: Duration = Duration::from_secs(30);

/// What the host looked like at one instant.
struct Sample {
    at: SystemTime,
    networks: BTreeSet<IpAddr>,
}

impl Sample {
    fn now() -> Self {
        Self {
            at: SystemTime::now(),
            networks: routable_networks(),
        }
    }
}

/// The networks beyond this host that it holds an address on: an IPv4 address,
/// or an IPv6 /64, so a rotating temporary address is not a new network. An
/// error reads as none; the cost is one extra pass when the list reads again.
fn routable_networks() -> BTreeSet<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces
                .iter()
                .filter(|interface| !interface.is_loopback() && !interface.is_link_local())
                .map(|interface| network(interface.ip()))
                .collect()
        })
        .unwrap_or_default()
}

fn network(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
    }
}

/// Whether the host slept or reached a new network between two samples. A
/// clock set back is no sleep.
fn woke(last: &Sample, next: &Sample) -> bool {
    let resumed = next
        .at
        .duration_since(last.at)
        .is_ok_and(|gap| gap > RESUME_GAP);
    resumed || !next.networks.is_subset(&last.networks)
}

/// Forces one pass per sample that woke. The first sample is the baseline.
fn watch(samples: impl IntoIterator<Item = Sample>, mut force_pass: impl FnMut()) {
    let mut samples = samples.into_iter();
    let Some(mut last) = samples.next() else {
        return;
    };
    for next in samples {
        if woke(&last, &next) {
            force_pass();
        }
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
            watch(samples, || host.force_pass());
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
            networks: addresses
                .iter()
                .map(|address| network(address.parse().expect("an address")))
                .collect(),
        }
    }

    fn passes(samples: Vec<Sample>) -> usize {
        let mut passes = 0;
        watch(samples, || passes += 1);
        passes
    }

    #[test]
    fn a_launch_and_a_steady_host_force_no_pass() {
        let wifi = ["192.168.1.20"];
        assert_eq!(passes(vec![sample(0, &wifi)]), 0);
        assert_eq!(
            passes(vec![sample(0, &wifi), sample(5, &wifi), sample(10, &wifi)]),
            0
        );
    }

    #[test]
    fn a_network_reconnect_forces_one_pass() {
        let wifi = ["192.168.1.20", "2001:db8::20"];
        assert_eq!(
            passes(vec![
                sample(0, &wifi),
                sample(5, &[]),
                sample(10, &wifi),
                sample(15, &wifi),
            ]),
            1
        );
    }

    /// A network that goes is not a moment a pass can land in; only its
    /// return is.
    #[test]
    fn losing_the_network_forces_no_pass() {
        assert_eq!(
            passes(vec![sample(0, &["192.168.1.20"]), sample(5, &[])]),
            0
        );
    }

    /// A tunnel or a container bridge that stays up leaves the host never
    /// offline, and the network it rejoins is still a reconnect.
    #[test]
    fn a_new_network_beside_one_that_stayed_up_is_a_reconnect() {
        assert_eq!(
            passes(vec![
                sample(0, &["100.64.0.7", "192.168.1.20"]),
                sample(5, &["100.64.0.7"]),
                sample(10, &["100.64.0.7", "10.0.0.31"]),
            ]),
            1
        );
    }

    #[test]
    fn a_rotated_temporary_address_is_not_a_reconnect() {
        assert_eq!(
            passes(vec![
                sample(0, &["2001:db8::1:aaaa"]),
                sample(5, &["2001:db8::1:aaaa", "2001:db8::1:bbbb"]),
                sample(10, &["2001:db8::1:bbbb"]),
            ]),
            0
        );
    }

    #[test]
    fn a_wake_from_sleep_forces_one_pass() {
        let wifi = ["192.168.1.20"];
        assert_eq!(
            passes(vec![
                sample(0, &wifi),
                sample(3_600, &wifi),
                sample(3_605, &wifi),
            ]),
            1
        );
    }

    #[test]
    fn a_short_stall_is_not_a_sleep() {
        let wifi = ["192.168.1.20"];
        assert_eq!(passes(vec![sample(0, &wifi), sample(30, &wifi)]), 0);
    }

    #[test]
    fn a_clock_set_back_is_not_a_sleep() {
        let wifi = ["192.168.1.20"];
        assert_eq!(passes(vec![sample(3_600, &wifi), sample(0, &wifi)]), 0);
    }

    #[test]
    fn a_wake_onto_a_new_network_forces_one_pass() {
        assert_eq!(
            passes(vec![
                sample(0, &["192.168.1.20"]),
                sample(3_600, &["10.0.0.31"])
            ]),
            1
        );
    }
}
