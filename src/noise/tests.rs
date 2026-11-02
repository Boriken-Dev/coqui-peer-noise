//! The published vectors of this protocol, whose handshake messages carry payloads the method never
//! sends, so they run against the objects beneath it.

use data_encoding::HEXLOWER;
use serde_json::Value;
use x25519_dalek::StaticSecret;

use super::{Cipher, DHLEN, Xx, is_canonical};
use crate::identity::Identity;

const PKCS8_PREFIX: &str = "302e020100300506032b656e04220420";

fn hex(text: &str) -> Vec<u8> {
    HEXLOWER.decode(text.as_bytes()).unwrap()
}

fn text<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector[name].as_str().unwrap()
}

fn identity(raw: &str) -> Identity {
    Identity::from_pkcs8_der(&hex(&format!("{PKCS8_PREFIX}{raw}"))).unwrap()
}

fn ephemeral(raw: &str) -> Box<StaticSecret> {
    let bytes: [u8; 32] = hex(raw).try_into().unwrap();
    Box::new(StaticSecret::from(bytes))
}

fn published() -> Vec<Value> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/published.json");
    let parsed: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    parsed["vectors"].as_array().unwrap().clone()
}

#[test]
fn the_published_vectors_are_reproduced_in_both_roles() {
    let vectors = published();
    assert!(vectors.len() >= 2, "both sources are present");
    for vector in vectors {
        let source = text(&vector, "source");
        let mut initiator = Xx::new(
            true,
            &hex(text(&vector, "init_prologue")),
            identity(text(&vector, "init_static")),
            ephemeral(text(&vector, "init_ephemeral")),
        );
        let mut responder = Xx::new(
            false,
            &hex(text(&vector, "resp_prologue")),
            identity(text(&vector, "resp_static")),
            ephemeral(text(&vector, "resp_ephemeral")),
        );
        let messages = vector["messages"].as_array().unwrap();
        assert!(messages.len() > 3, "{source}: transport messages follow");
        for (index, message) in messages.iter().take(3).enumerate() {
            let (payload, expected) = (
                hex(text(message, "payload")),
                hex(text(message, "ciphertext")),
            );
            let (sender, receiver) = if index % 2 == 0 {
                (&mut initiator, &mut responder)
            } else {
                (&mut responder, &mut initiator)
            };
            assert_eq!(
                sender.write_message(&payload).unwrap(),
                expected,
                "{source}: message {index}"
            );
            assert_eq!(receiver.read_message(&expected).unwrap(), payload);
        }
        let (mut at_initiator, mut at_responder) =
            (initiator.split().unwrap(), responder.split().unwrap());
        assert_eq!(at_initiator.h, at_responder.h);
        if let Some(hash) = vector.get("handshake_hash") {
            assert_eq!(
                at_initiator.h.to_vec(),
                hex(hash.as_str().unwrap()),
                "{source}"
            );
        }
        for (index, message) in messages.iter().enumerate().skip(3) {
            let (payload, expected) = (
                hex(text(message, "payload")),
                hex(text(message, "ciphertext")),
            );
            let (sending, receiving) = if index % 2 == 0 {
                (
                    &mut at_initiator.initiator_to_responder,
                    &mut at_responder.initiator_to_responder,
                )
            } else {
                (
                    &mut at_responder.responder_to_initiator,
                    &mut at_initiator.responder_to_initiator,
                )
            };
            assert_eq!(
                sending.encrypt(&[], &payload).unwrap(),
                expected,
                "{source}"
            );
            assert_eq!(receiving.decrypt(&[], &expected).unwrap(), payload);
        }
    }
}

#[test]
fn the_reserved_nonce_is_never_used_by_a_message() {
    let mut cipher = Cipher::new(&[7; 32]);
    cipher.set_nonce(u64::MAX - 1);
    assert!(cipher.encrypt(&[], b"the last").is_some());
    assert!(cipher.encrypt(&[], b"one more").is_none());
    assert_eq!(cipher.remaining(), 0);
    // A ciphertext that is valid at that nonce, as REKEY would make one.
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::{Aead, KeyInit};
    let mut iv = [0xffu8; 12];
    iv[..4].fill(0);
    let valid = Aes256Gcm::new_from_slice(&[7; 32])
        .unwrap()
        .encrypt(&iv.into(), [0u8; 32].as_slice())
        .unwrap();
    let mut other = Cipher::new(&[7; 32]);
    other.set_nonce(u64::MAX);
    assert!(other.decrypt(&[], &valid).is_none());
}

#[test]
fn rekey_is_the_first_32_bytes_at_the_reserved_nonce_and_the_nonce_carries_on() {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::{Aead, KeyInit};
    let key = [9u8; 32];
    let mut iv = [0xffu8; 12];
    iv[..4].fill(0);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let expected = cipher.encrypt(&iv.into(), [0u8; 32].as_slice()).unwrap();
    let mut rekeyed = Cipher::new(&key);
    assert!(rekeyed.encrypt(&[], b"before").is_some());
    assert!(rekeyed.rekey());
    let mut direct = Cipher::new(&expected[..32]);
    direct.set_nonce(1);
    assert_eq!(
        rekeyed.encrypt(&[], b"after"),
        direct.encrypt(&[], b"after")
    );
    assert_eq!(rekeyed.remaining(), u64::MAX - 2);
}

#[test]
fn only_one_encoding_of_a_value_is_canonical() {
    let mut p = [0xffu8; DHLEN];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut below_p = p;
    below_p[0] = 0xec;
    assert!(is_canonical(&below_p));
    assert!(!is_canonical(&p));
    let mut above_p = p;
    above_p[0] = 0xee;
    assert!(!is_canonical(&above_p));
    assert!(is_canonical(&[0; DHLEN]));
    let mut high_bit = [0u8; DHLEN];
    high_bit[31] = 0x80;
    assert!(!is_canonical(&high_bit));
    let mut middle = p;
    middle[15] = 0xfe;
    assert!(is_canonical(&middle), "below p whatever its low byte");
}

#[test]
fn an_attacker_with_no_private_key_cannot_prove_a_small_order_static_key() {
    // The attacker follows the protocol up to its static key, and from there knows every DH output
    // is all zeros, so it can make the tag.
    let responder_identity = Identity::generate().unwrap();
    let attacker_identity = Identity::generate().unwrap();
    let mut responder = Xx::new(false, b"", responder_identity, ephemeral(&"11".repeat(32)));
    let mut attacker = Xx::new(true, b"", attacker_identity, ephemeral(&"22".repeat(32)));
    responder
        .read_message(&attacker.write_message(&[]).unwrap())
        .unwrap();
    attacker
        .read_message(&responder.write_message(&[]).unwrap())
        .unwrap();

    let symmetric = attacker.symmetric_mut();
    let mut third = symmetric.encrypt_and_hash(&[0u8; 32]).unwrap();
    symmetric.mix_key(&[0u8; 32]);
    third.extend_from_slice(&symmetric.encrypt_and_hash(&[]).unwrap());

    assert!(matches!(
        responder.read_message(&third),
        Err(crate::error::Error::Malformed)
    ));
}
