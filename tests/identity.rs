//! Keys: their text form, files and refusals, and the id a standard tool computes.

mod support;

use coqui_peer::{KeyMaterial, PeerId};
use coqui_peer_noise::{Error, Identity, METHOD, PROTOCOL_NAME};
use support::{dh_of, identity_of, small_order};

// `openssl genpkey -algorithm x25519`, a throwaway test key.
const OPENSSL: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIDi29y8jdUtbXzmuAH6tYOxcbCD7wqdUsLfpBzNO5xdV
-----END PRIVATE KEY-----
";
/// `openssl pkey -pubout -outform DER | sha256sum` of that key.
const OPENSSL_ID: &str = "sha256:85bdd198338bedb20428aab5683b1c5092461a721db1a5bd110cd7577d0f94c2";
/// `openssl pkey -pubout` of that key, the body of its PEM block.
const OPENSSL_PUBLIC: [u8; 44] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, 0xc5, 0x78, 0x5a, 0xaa,
    0x5d, 0xcf, 0x21, 0x0c, 0x31, 0x11, 0x17, 0x11, 0x8e, 0x4a, 0x06, 0x7b, 0xe6, 0xee, 0xfe, 0x9c,
    0x72, 0xe2, 0xfd, 0xa6, 0xd9, 0xa4, 0x04, 0xae, 0x79, 0x69, 0x3a, 0x70,
];

#[test]
fn the_protocol_name_and_method_are_the_documented_ones() {
    assert_eq!(PROTOCOL_NAME, "Noise_XX_25519_AESGCM_SHA256");
    assert_eq!(METHOD, "noise");
}

#[test]
fn a_key_openssl_wrote_has_the_public_key_and_the_id_openssl_computes() {
    let identity = Identity::from_pkcs8_pem(OPENSSL).unwrap();
    assert_eq!(*identity.spki_der(), OPENSSL_PUBLIC);
    assert_eq!(identity.peer_id().to_string(), OPENSSL_ID);
    assert_eq!(identity.public_key()[..], OPENSSL_PUBLIC[12..]);
}

#[test]
fn a_key_is_stored_as_a_store_requires_and_its_id_is_the_stores() {
    let identity = Identity::generate().unwrap();
    let material = identity.key_material();
    assert_eq!(material.method, "noise");
    assert_eq!(material.label, "PUBLIC KEY");
    assert_eq!(material.bytes, identity.spki_der());
    assert_eq!(material.id(), identity.peer_id());
    assert!(KeyMaterial::new(material.method, material.label, material.bytes).is_ok());
    // A PeerId in its text form parses back, in the only digest an id of this method has.
    let id: PeerId = identity.peer_id().to_string().parse().unwrap();
    assert_eq!(id, identity.peer_id());
}

#[test]
fn a_text_form_naming_the_curve_is_not_a_peer_id() {
    // Which method a key belongs to is `KeyMaterial::method`; an id is a digest's.
    let text = format!("x25519:{}", "0".repeat(64));
    assert!(text.parse::<PeerId>().is_err());
    assert_eq!(
        Identity::generate().unwrap().peer_id().digest(),
        coqui_peer::Digest::Sha256
    );
}

#[test]
fn a_key_round_trips_through_pem_and_a_file_and_is_never_replaced() {
    let identity = Identity::generate().unwrap();
    let pem = identity.to_pkcs8_pem().unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert_eq!(
        Identity::from_pkcs8_pem(&pem).unwrap().peer_id(),
        identity.peer_id()
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("identity.pem");
    assert!(Identity::read(&path).unwrap().is_none());
    identity.write_new(&path).unwrap();
    assert_eq!(
        Identity::read(&path).unwrap().unwrap().peer_id(),
        identity.peer_id()
    );
    assert!(matches!(
        Identity::generate().unwrap().write_new(&path),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(
        Identity::open_or_create(&path).unwrap().peer_id(),
        identity.peer_id()
    );
    let other = dir.path().join("other.pem");
    let created = Identity::open_or_create(&other).unwrap();
    assert_eq!(
        Identity::open_or_create(&other).unwrap().peer_id(),
        created.peer_id()
    );
}

#[test]
fn what_is_not_an_x25519_pkcs8_key_is_refused_without_quoting_it() {
    let certificate = OPENSSL.replace("PRIVATE KEY", "CERTIFICATE");
    let unterminated = OPENSSL.replace("-----END PRIVATE KEY-----", "");
    // The P-256 test key of a neighbouring method.
    let other_curve = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQX767IF1SnjFE9j0
FGjSyYTimEy31oJ2peld37bnJbehRANCAAQiTXbXAHFJHi+C1d8eqz//HeB6Czsm
zCGbypT2YjCrhS1DZH++dlNVgt6w3FyxPIE+PPHBFLBvlv4Qm8QsV9Qp
-----END PRIVATE KEY-----
";
    for text in [
        "",
        "secret text",
        certificate.as_str(),
        unterminated.as_str(),
        other_curve,
    ] {
        let error = Identity::from_pkcs8_pem(text).unwrap_err();
        assert!(matches!(error, Error::Key));
        assert!(!error.to_string().contains("secret"));
    }
    assert!(matches!(
        Identity::from_pkcs8_der(&[0; 48]),
        Err(Error::Key)
    ));
    let mut der = support::pkcs8([1; 32]);
    der.push(0);
    assert!(matches!(Identity::from_pkcs8_der(&der), Err(Error::Key)));
    der.truncate(47);
    assert!(matches!(Identity::from_pkcs8_der(&der), Err(Error::Key)));
}

#[test]
fn a_failing_source_gives_an_error() {
    let failing = coqui_peer_noise::Random::from_fn(|_| Err(coqui_peer::Error::Random));
    assert!(matches!(
        Identity::generate_with(&failing),
        Err(Error::Random)
    ));
}

#[test]
fn an_identitys_debug_shows_its_id_and_no_key() {
    let identity = identity_of([9; 32]);
    let debug = format!("{identity:?}");
    assert!(debug.contains(&identity.peer_id().to_string()));
    assert!(!debug.contains("0909"));
}

#[test]
fn every_listed_small_order_point_gives_x25519_all_zeros() {
    for point in small_order() {
        assert_eq!(dh_of([0x77; 32], point), [0; 32]);
        assert_eq!(dh_of([0x31; 32], point), [0; 32]);
    }
}
