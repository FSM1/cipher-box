//! Conformance kit: [`Mailbox`] until-acked retention and idempotency.

use crate::seams::Mailbox;

/// Runs the `Mailbox` contract against an implementation.
///
/// `mailbox` must be bound to the inbox of `own_recipient_public_key` (the
/// kit posts to itself) and that inbox must start empty.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<M>(mailbox: &M, own_recipient_public_key: &[u8])
where
    M: Mailbox,
{
    assert!(
        mailbox.poll().await.unwrap().is_empty(),
        "the inbox must start empty"
    );

    // Post, then poll repeatedly: until-acked retention.
    mailbox
        .post(own_recipient_public_key, b"sealed-1", "idem-1")
        .await
        .unwrap();
    let first_poll = mailbox.poll().await.unwrap();
    assert_eq!(first_poll.len(), 1);
    assert_eq!(
        first_poll[0].sealed_payload, b"sealed-1",
        "the sealed payload must arrive verbatim"
    );
    assert_eq!(
        mailbox.poll().await.unwrap().len(),
        1,
        "an unacked item must survive repeated polls"
    );

    // Idempotent post: an already-seen idempotency key creates no second
    // item.
    mailbox
        .post(own_recipient_public_key, b"sealed-1", "idem-1")
        .await
        .unwrap();
    assert_eq!(
        mailbox.poll().await.unwrap().len(),
        1,
        "re-posting an already-seen idempotency key must not duplicate"
    );

    // A distinct key is a distinct item.
    mailbox
        .post(own_recipient_public_key, b"sealed-2", "idem-2")
        .await
        .unwrap();
    let items = mailbox.poll().await.unwrap();
    assert_eq!(items.len(), 2);
    let payloads: Vec<&[u8]> = items.iter().map(|i| i.sealed_payload.as_slice()).collect();
    assert!(payloads.contains(&b"sealed-1".as_slice()));
    assert!(payloads.contains(&b"sealed-2".as_slice()));

    // Ack deletes exactly the acked item; acking is idempotent.
    let first_id = items
        .iter()
        .find(|i| i.sealed_payload == b"sealed-1")
        .expect("item present")
        .item_id
        .clone();
    mailbox.ack(&first_id).await.unwrap();
    mailbox.ack(&first_id).await.unwrap();
    let remaining = mailbox.poll().await.unwrap();
    assert_eq!(remaining.len(), 1, "ack must delete exactly one item");
    assert_eq!(remaining[0].sealed_payload, b"sealed-2");

    mailbox.ack(&remaining[0].item_id).await.unwrap();
    assert!(
        mailbox.poll().await.unwrap().is_empty(),
        "an acked inbox must poll empty"
    );
}
