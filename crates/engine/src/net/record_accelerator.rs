//! The record plane's credential splice: the session read pseudonym reaches
//! the CipherBox routing accelerator's GET leg and nothing else
//! (blueprint/api.md "The front covers both read legs").

use zeroize::Zeroizing;

use crate::content::read::{SessionBearer, carries_credentials_safely};
use crate::seams::{EndpointId, RecordTransport, SeamResult, check_bearer};

/// The host's [`RecordTransport`] with the read pseudonym armed on one endpoint.
///
/// The engine wraps the seam once at construction and splices the credential
/// here, so no caller decides which endpoint is shown one. The accelerator
/// names itself ([`RecordTransport::accelerator`]); the engine decides what it
/// may be shown.
#[derive(Clone)]
pub struct RecordAccelerator<T> {
    inner: T,
    /// The endpoint the pseudonym may reach, once it has cleared the transport
    /// rule. `None` leaves every endpoint unauthenticated.
    armed: Option<EndpointId>,
    bearer: SessionBearer,
}

impl<T: RecordTransport> RecordAccelerator<T> {
    /// Arms `bearer` on the transport's own accelerator, and only over a
    /// transport that can keep a credential — an endpoint denied it still
    /// serves reads, just unauthenticated.
    pub(crate) fn new(inner: T, bearer: SessionBearer) -> Self {
        let armed = inner
            .accelerator()
            .filter(|endpoint| carries_credentials_safely(&endpoint.0));
        Self {
            inner,
            armed,
            bearer,
        }
    }

    /// The credential `endpoint` may be shown, read from the shared cell at
    /// request time. A token that cannot be a header value is withheld rather
    /// than sent: the leg then reads unauthenticated, and fan-out treats its
    /// refusal as availability.
    fn credential(&self, endpoint: &EndpointId) -> Option<Zeroizing<String>> {
        if self.armed.as_ref() != Some(endpoint) {
            return None;
        }
        self.bearer
            .peek()
            .filter(|token| check_bearer(token).is_ok())
    }
}

impl<T: RecordTransport> RecordTransport for RecordAccelerator<T> {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.inner.endpoints()
    }

    /// The endpoint this wrapper armed: the inner accelerator when it can keep
    /// a credential, and nothing otherwise.
    fn accelerator(&self) -> Option<EndpointId> {
        self.armed.clone()
    }

    /// The credential is this wrapper's decision, so `_bearer` is discarded: a
    /// caller cannot name the endpoint that sees the pseudonym.
    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
        _bearer: Option<&str>,
    ) -> SeamResult<Option<Vec<u8>>> {
        let credential = self.credential(endpoint);
        self.inner
            .get_record(
                endpoint,
                routing_key,
                max_bytes,
                credential.as_ref().map(|token| token.as_str()),
            )
            .await
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        self.inner.put_record(endpoint, routing_key, record).await
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::ipns::IpnsName;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::net::fanout::{FanoutRecord, fanout_get_classified};
    use crate::seams::{SeamError, SeamResult};
    use crate::testkit::block_on;

    const ACCELERATOR: &str = "https://routing.cipherbox.test";
    const PUBLIC: &str = "https://delegated-ipfs.example";
    const PSEUDONYM: &str = "read-pseudonym";

    /// Records the credential each leg was shown, and answers the accelerator's
    /// GET with a gate refusal — the staging front's 403 shape.
    struct RefusesTheGatedLeg {
        accelerator: Option<EndpointId>,
        shown: RefCell<Vec<(String, Option<String>)>>,
    }

    impl RefusesTheGatedLeg {
        fn new(accelerator: Option<&str>) -> Self {
            Self {
                accelerator: accelerator.map(EndpointId::new),
                shown: RefCell::new(Vec::new()),
            }
        }

        /// The credential the endpoint's most recent GET carried.
        fn shown_to(&self, endpoint: &str) -> Option<String> {
            self.shown
                .borrow()
                .iter()
                .rev()
                .find(|(seen, _)| seen == endpoint)
                .and_then(|(_, bearer)| bearer.clone())
        }

        fn asked(&self, endpoint: &str) -> usize {
            self.shown
                .borrow()
                .iter()
                .filter(|(seen, _)| seen == endpoint)
                .count()
        }
    }

    impl RecordTransport for RefusesTheGatedLeg {
        fn endpoints(&self) -> Vec<EndpointId> {
            vec![EndpointId::new(ACCELERATOR), EndpointId::new(PUBLIC)]
        }

        fn accelerator(&self) -> Option<EndpointId> {
            self.accelerator.clone()
        }

        async fn get_record(
            &self,
            endpoint: &EndpointId,
            _routing_key: &str,
            _max_bytes: usize,
            bearer: Option<&str>,
        ) -> SeamResult<Option<Vec<u8>>> {
            self.shown
                .borrow_mut()
                .push((endpoint.0.clone(), bearer.map(str::to_owned)));
            if endpoint.0 == ACCELERATOR {
                return Err(SeamError::new("status 403"));
            }
            Ok(None)
        }

        async fn put_record(
            &self,
            _endpoint: &EndpointId,
            _routing_key: &str,
            _record: &[u8],
        ) -> SeamResult<()> {
            Ok(())
        }
    }

    fn armed_with(
        inner: RefusesTheGatedLeg,
        bearer: SessionBearer,
    ) -> RecordAccelerator<RefusesTheGatedLeg> {
        RecordAccelerator::new(inner, bearer)
    }

    fn armed(inner: RefusesTheGatedLeg) -> RecordAccelerator<RefusesTheGatedLeg> {
        let bearer = SessionBearer::default();
        bearer.set(PSEUDONYM);
        armed_with(inner, bearer)
    }

    fn name() -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([3u8; 32]).verifying_key())
    }

    #[test]
    fn the_pseudonym_reaches_the_accelerator_and_no_public_endpoint() {
        let transport = armed(RefusesTheGatedLeg::new(Some(ACCELERATOR)));

        block_on(fanout_get_classified(&transport, &name()));

        assert_eq!(
            transport.inner.shown_to(ACCELERATOR).as_deref(),
            Some(PSEUDONYM)
        );
        assert_eq!(
            transport.inner.shown_to(PUBLIC),
            None,
            "a public endpoint is shown no credential"
        );
    }

    #[test]
    fn a_cleartext_accelerator_is_never_armed() {
        const CLEARTEXT: &str = "http://routing.cipherbox.test";
        let transport = armed(RefusesTheGatedLeg::new(Some(CLEARTEXT)));

        assert_eq!(transport.credential(&EndpointId::new(CLEARTEXT)), None);
        assert_eq!(transport.accelerator(), None);
    }

    /// The splice is the wrapper's alone: a caller naming a public endpoint and
    /// a token of its own gets neither through.
    #[test]
    fn a_caller_supplied_bearer_never_reaches_the_transport() {
        let transport = armed(RefusesTheGatedLeg::new(Some(ACCELERATOR)));

        block_on(transport.get_record(
            &EndpointId::new(PUBLIC),
            "a-name",
            1024,
            Some("a-caller-token"),
        ))
        .expect("the public leg answers");

        assert_eq!(transport.inner.shown_to(PUBLIC), None);
    }

    /// A token that cannot be a header value is withheld, and the leg is still
    /// read — availability, never a request the host must reject.
    #[test]
    fn a_token_that_cannot_be_a_header_value_is_withheld() {
        let bearer = SessionBearer::default();
        bearer.set("token with\na newline");
        let transport = armed_with(RefusesTheGatedLeg::new(Some(ACCELERATOR)), bearer);

        block_on(fanout_get_classified(&transport, &name()));

        assert_eq!(transport.inner.asked(ACCELERATOR), 1);
        assert_eq!(transport.inner.shown_to(ACCELERATOR), None);
    }

    /// Logout seals the one cell every clone shares, so a background task that
    /// cloned the transport stops presenting the pseudonym too.
    #[test]
    fn a_sealed_cell_disarms_the_leg() {
        let bearer = SessionBearer::default();
        bearer.set(PSEUDONYM);
        let transport = armed_with(RefusesTheGatedLeg::new(Some(ACCELERATOR)), bearer.clone());

        bearer.clear();
        block_on(fanout_get_classified(&transport, &name()));
        assert_eq!(transport.inner.shown_to(ACCELERATOR), None);

        bearer.set(PSEUDONYM);
        block_on(fanout_get_classified(&transport, &name()));
        assert_eq!(
            transport.inner.shown_to(ACCELERATOR).as_deref(),
            Some(PSEUDONYM),
            "a cleared cell is re-armable; the token is read at request time"
        );

        bearer.seal();
        bearer.set(PSEUDONYM);
        let sealed = armed_with(RefusesTheGatedLeg::new(Some(ACCELERATOR)), bearer);
        block_on(fanout_get_classified(&sealed, &name()));
        assert_eq!(sealed.inner.shown_to(ACCELERATOR), None);
    }

    #[test]
    fn no_endpoint_is_armed_when_the_host_configured_no_accelerator() {
        let transport = armed(RefusesTheGatedLeg::new(None));

        block_on(fanout_get_classified(&transport, &name()));

        assert_eq!(transport.inner.shown_to(ACCELERATOR), None);
        assert_eq!(transport.inner.shown_to(PUBLIC), None);
    }

    /// A refused gated leg beside one vacant public answer says nothing about
    /// the name: the set did not agree it is vacant.
    #[test]
    fn a_refused_accelerator_beside_an_absent_public_answer_stays_unavailable() {
        let transport = armed(RefusesTheGatedLeg::new(Some(ACCELERATOR)));

        assert!(matches!(
            block_on(fanout_get_classified(&transport, &name())),
            FanoutRecord::Unavailable(_)
        ));
    }
}
