//! A dialer whose private key is held elsewhere: the handshake stops where the key is used, takes
//! the Diffie-Hellman result the caller computed, and ends in the session a full key gives.

use coqui_peer::{Handshake, Method};
use coqui_peer_noise::{Error, Identity, Noise, NoiseHandshake, PairingMethod, Trust};
use x25519_dalek::{PublicKey, StaticSecret};

const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// A key as a full identity, its secret, and the identity holding only its public half.
fn split_key(seed: u8) -> (Identity, StaticSecret, Identity) {
    let secret = [seed; 32];
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&secret);
    let full = Identity::from_pkcs8_der(&der).unwrap();
    let held = Identity::from_public_key(full.public_key()).unwrap();
    (full, StaticSecret::from(secret), held)
}

/// What the caller's key computes: X25519 of its secret with the responder's ephemeral key.
fn shared(secret: &StaticSecret, ephemeral: [u8; 32]) -> [u8; 32] {
    secret
        .diffie_hellman(&PublicKey::from(ephemeral))
        .to_bytes()
}

fn methods(dialer: &Identity, listener: &Identity) -> (Noise, Noise) {
    (
        Noise::builder()
            .identity(dialer.clone())
            .responders(Trust::pinned([listener.peer_id()]))
            .build()
            .unwrap(),
        Noise::builder()
            .identity(listener.clone())
            .initiators(Trust::pinned([dialer.peer_id()]))
            .build()
            .unwrap(),
    )
}

/// The dialer's handshake paused at its third message, and the listener's waiting for it.
fn paused(dialer: &Identity) -> (NoiseHandshake, NoiseHandshake) {
    let listener = Identity::generate().unwrap();
    let (dial, listen) = methods(dialer, &listener);
    let (mut dialing, mut listening) = (dial.initiate().unwrap(), listen.respond(None).unwrap());
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    dialing
        .receive(&listening.transmit().unwrap().unwrap())
        .unwrap();
    (dialing, listening)
}

#[test]
fn a_held_key_has_the_id_of_the_full_key_and_nothing_to_write() {
    let (full, _, held) = split_key(7);
    assert_eq!(held.peer_id(), full.peer_id());
    assert_eq!(held.public_key(), full.public_key());
    assert_eq!(held.spki_der(), full.spki_der());
    assert!(full.holds_private_key() && !held.holds_private_key());
    assert!(matches!(held.to_pkcs8_pem(), Err(Error::Key)));
    // X25519 masks the top bit, so a key with it set would be a second id for the same key.
    let mut high = *full.public_key();
    high[31] |= 0x80;
    assert!(matches!(Identity::from_public_key(&high), Err(Error::Key)));
}

#[test]
fn a_held_key_cannot_accept_a_dial() {
    let (_, _, held) = split_key(1);
    let other = Identity::generate().unwrap();
    let method = Noise::builder()
        .identity(held)
        .initiators(Trust::pinned([other.peer_id()]))
        .build()
        .unwrap();
    assert!(matches!(method.respond(None), Err(Error::Unsupported)));
}

#[test]
fn the_handshake_pauses_after_the_second_message_and_goes_on_with_the_callers_result() {
    let (full, secret, held) = split_key(3);
    let listener = Identity::generate().unwrap();
    let (dial, listen) = methods(&held, &listener);
    let (mut dialing, mut listening) = (dial.initiate().unwrap(), listen.respond(None).unwrap());
    assert_eq!(dialing.pending_static_dh(), None);
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    assert_eq!(dialing.pending_static_dh(), None);
    dialing
        .receive(&listening.transmit().unwrap().unwrap())
        .unwrap();

    let ephemeral = dialing.pending_static_dh().expect("paused");
    assert_eq!(
        dialing.transmit().unwrap(),
        None,
        "nothing to send until the result is in"
    );
    assert!(!dialing.is_complete());
    dialing
        .provide_static_dh(&shared(&secret, ephemeral))
        .unwrap();
    assert_eq!(dialing.pending_static_dh(), None);
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    assert!(dialing.is_complete() && listening.is_complete());

    let (mut at_dialer, mut at_listener) = (dialing.finish().unwrap(), listening.finish().unwrap());
    assert_eq!(at_listener.peer, full.peer_id());
    assert_eq!(at_dialer.session.id(), at_listener.session.id());
    let record = at_dialer.session.seal(b"over the held key").unwrap();
    assert_eq!(
        at_listener.session.open(&record).unwrap().as_deref(),
        Some(&b"over the held key"[..])
    );
}

#[test]
fn an_all_zero_result_is_refused_and_ends_the_handshake() {
    let (_, _, held) = split_key(4);
    let (mut dialing, _listening) = paused(&held);
    assert!(matches!(
        dialing.provide_static_dh(&[0; 32]),
        Err(Error::Malformed)
    ));
    assert_eq!(dialing.pending_static_dh(), None);
    assert!(matches!(dialing.transmit(), Err(Error::State)));
    assert!(matches!(
        dialing.provide_static_dh(&[1; 32]),
        Err(Error::State)
    ));
}

#[test]
fn a_message_while_paused_ends_the_handshake() {
    let (_, _, held) = split_key(10);
    let (mut dialing, _listening) = paused(&held);
    assert!(matches!(dialing.receive(&[0; 32]), Err(Error::State)));
    assert_eq!(dialing.pending_static_dh(), None);
    assert!(matches!(
        dialing.provide_static_dh(&[1; 32]),
        Err(Error::State)
    ));
}

#[test]
fn a_result_of_the_wrong_length_is_refused() {
    let (_, _, held) = split_key(5);
    for bad in [&[][..], &[1u8; 31][..], &[1u8; 33][..]] {
        let (mut dialing, _listening) = paused(&held);
        assert!(matches!(
            dialing.provide_static_dh(bad),
            Err(Error::Malformed)
        ));
        assert!(matches!(dialing.transmit(), Err(Error::State)));
    }
}

#[test]
fn a_result_of_another_key_does_not_prove_the_held_one() {
    let (_, _, held) = split_key(6);
    let (mut dialing, mut listening) = paused(&held);
    let ephemeral = dialing.pending_static_dh().unwrap();
    let (_, intruder, _) = split_key(9);
    dialing
        .provide_static_dh(&shared(&intruder, ephemeral))
        .unwrap();
    let third = dialing.transmit().unwrap().unwrap();
    assert!(
        listening.receive(&third).is_err(),
        "the listener refuses a third message the key did not make"
    );
}

#[test]
fn nothing_is_pending_for_a_full_key_or_before_the_second_message() {
    let (full, _, held) = split_key(2);
    let listener = Identity::generate().unwrap();
    let (dial, listen) = methods(&full, &listener);
    let (mut dialing, mut listening) = (dial.initiate().unwrap(), listen.respond(None).unwrap());
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    dialing
        .receive(&listening.transmit().unwrap().unwrap())
        .unwrap();
    assert_eq!(dialing.pending_static_dh(), None);
    assert!(matches!(
        dialing.provide_static_dh(&[1; 32]),
        Err(Error::State)
    ));
    assert!(dialing.transmit().unwrap().is_some());

    let mut early = methods(&held, &listener).0.initiate().unwrap();
    assert!(matches!(
        early.provide_static_dh(&[1; 32]),
        Err(Error::State)
    ));
}

#[test]
fn a_held_key_pairs_the_same_way() {
    let (full, secret, held) = split_key(8);
    let joiner = PairingMethod::builder().identity(held).build().unwrap();
    let responder = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .build()
        .unwrap();
    let (mut joining, mut responding) =
        (joiner.initiate().unwrap(), responder.respond(None).unwrap());
    responding
        .receive(&joining.transmit().unwrap().unwrap())
        .unwrap();
    joining
        .receive(&responding.transmit().unwrap().unwrap())
        .unwrap();
    let ephemeral = joining.pending_static_dh().expect("paused");
    assert!(!joining.is_complete());
    joining
        .provide_static_dh(&shared(&secret, ephemeral))
        .unwrap();
    responding
        .receive(&joining.transmit().unwrap().unwrap())
        .unwrap();
    let (at_joiner, at_responder) = (joining.finish().unwrap(), responding.finish().unwrap());
    assert_eq!(at_responder.peer, full.peer_id());
    assert_eq!(at_joiner.session.id(), at_responder.session.id());
}
