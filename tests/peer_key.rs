//! After a handshake each end holds the other's static public key, as the key material its id is the digest of, so a caller can
//! make a Diffie-Hellman with it. Nothing of either private key is exposed.

use coqui_peer::{Handshake, Method};
use coqui_peer_noise::{Identity, Noise, NoiseHandshake, Trust};
use x25519_dalek::{PublicKey, StaticSecret};

fn pair(dialer: &Identity, listener: &Identity) -> (NoiseHandshake, NoiseHandshake) {
    let dial = Noise::builder()
        .identity(dialer.clone())
        .responders(Trust::pinned([listener.peer_id()]))
        .build()
        .unwrap();
    let listen = Noise::builder()
        .identity(listener.clone())
        .initiators(Trust::pinned([dialer.peer_id()]))
        .build()
        .unwrap();
    (dial.initiate().unwrap(), listen.respond(None).unwrap())
}

#[test]
fn each_end_holds_the_others_static_public_key() {
    let (dialer, listener) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (mut dialing, mut listening) = pair(&dialer, &listener);
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    dialing
        .receive(&listening.transmit().unwrap().unwrap())
        .unwrap();
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    let (at_dialer, at_listener) = (dialing.finish().unwrap(), listening.finish().unwrap());

    let heard_by_dialer = at_dialer.key.expect("the listener's key");
    let heard_by_listener = at_listener.key.expect("the dialer's key");
    assert_eq!(heard_by_dialer.bytes, listener.spki_der().to_vec());
    assert_eq!(heard_by_listener.bytes, dialer.spki_der().to_vec());
    assert_eq!(heard_by_dialer.id(), at_dialer.peer);
    assert_eq!(heard_by_listener.id(), at_listener.peer);
    // The 32 bytes a Diffie-Hellman takes are the end of the SubjectPublicKeyInfo.
    assert_eq!(&heard_by_dialer.bytes[12..], listener.public_key());
}

#[test]
fn a_dialer_whose_key_is_held_elsewhere_learns_the_listeners_key() {
    const PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
        0x20,
    ];
    let secret = [9_u8; 32];
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&secret);
    let held =
        Identity::from_public_key(Identity::from_pkcs8_der(&der).unwrap().public_key()).unwrap();
    let listener = Identity::generate().unwrap();
    let (mut dialing, mut listening) = pair(&held, &listener);
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    dialing
        .receive(&listening.transmit().unwrap().unwrap())
        .unwrap();
    let ephemeral = dialing.pending_static_dh().expect("paused");
    let shared = StaticSecret::from(secret).diffie_hellman(&PublicKey::from(ephemeral));
    dialing.provide_static_dh(shared.as_bytes()).unwrap();
    listening
        .receive(&dialing.transmit().unwrap().unwrap())
        .unwrap();
    let at_dialer = dialing.finish().unwrap();
    assert_eq!(at_dialer.key.unwrap().bytes, listener.spki_der().to_vec());
    assert_eq!(
        listening.finish().unwrap().key.unwrap().bytes,
        held.spki_der().to_vec()
    );
}
