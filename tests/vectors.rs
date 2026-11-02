//! Shared vectors both languages read: fixed keys give fixed bytes, and a list of what must be refused,
//! at the stage named. `tests/vectors/session.json` regenerates with
//! `cargo test --test vectors -- --ignored regenerate`; a change there is a change to the wire.
//! The bytes are also reached with `snow`, so they are not only this crate agreeing with itself.

mod support;

use std::path::PathBuf;

use coqui_peer::{Handshake, Method};
use coqui_peer_noise::{Error, Identity, Noise, NoiseHandshake, PROFILE, PROTOCOL_NAME, Trust};
use data_encoding::HEXLOWER;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::{
    Attacker, Forger, dh_of, identity_of, p_plus, pkcs8, public_of, rekeyed, scripted, small_order,
};

const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x33; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x44; 32];
const BINDING: &[u8] = b"an outer channel's exporter";
/// So that a record of three small messages crosses it.
const KEY_LIMIT: u64 = 300;
const LONG_MESSAGE: usize = 70_000;

fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

fn long_message() -> Vec<u8> {
    (0..LONG_MESSAGE)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn prologue(binding: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [PROFILE.as_bytes(), binding] {
        out.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn initiator() -> Noise {
    Noise::new(identity_of(INITIATOR_STATIC))
        .with_responders(Trust::pinned([identity_of(RESPONDER_STATIC).peer_id()]))
        .with_random(scripted(&[INITIATOR_EPHEMERAL]))
}

fn responder() -> Noise {
    Noise::new(identity_of(RESPONDER_STATIC))
        .with_initiators(Trust::pinned([identity_of(INITIATOR_STATIC).peer_id()]))
        .with_random(scripted(&[RESPONDER_EPHEMERAL]))
}

fn side(identity: &Identity, raw: [u8; 32], ephemeral: [u8; 32]) -> Value {
    json!({
        "pkcs8": hex(&pkcs8(raw)),
        "public": hex(identity.public_key()),
        "spki": hex(identity.spki_der()),
        "peerId": identity.peer_id().to_string(),
        "ephemeralPkcs8": hex(&pkcs8(ephemeral)),
        "ephemeralPublic": hex(&public_of(ephemeral)),
    })
}

fn flipped(message: &[u8], index: usize) -> Vec<u8> {
    let mut out = message.to_vec();
    out[index] ^= 1;
    out
}

/// The attacker's chain just after the responder's `ee`, as the initiator will compute it.
fn up_to_ee(first: &[u8], second_e: &[u8; 32]) -> Attacker {
    let mut state = Attacker::new(&prologue(b""));
    state.mix_hash(first);
    state.mix_hash(&[]);
    state.mix_hash(second_e);
    state.mix_key(&dh_of(RESPONDER_EPHEMERAL, first.try_into().unwrap()));
    state
}

/// A second message presenting `key` as the responder's static, whose tag is right if the DH of that
/// key with the initiator's ephemeral is `es`.
fn second_presenting(first: &[u8], key: [u8; 32], es: [u8; 32]) -> Vec<u8> {
    let e = public_of(RESPONDER_EPHEMERAL);
    let mut state = up_to_ee(first, &e);
    let mut out = e.to_vec();
    out.extend_from_slice(&state.encrypt_and_hash(&key));
    state.mix_key(&es);
    out.extend_from_slice(&state.encrypt_and_hash(&[]));
    out
}

/// The chain after a real second message, as the responder holds it.
fn after_second(first: &[u8]) -> Attacker {
    let e = public_of(RESPONDER_EPHEMERAL);
    let mut state = up_to_ee(first, &e);
    state.encrypt_and_hash(&public_of(RESPONDER_STATIC));
    state.mix_key(&dh_of(INITIATOR_EPHEMERAL, public_of(RESPONDER_STATIC)));
    state.encrypt_and_hash(&[]);
    state
}

/// A third message presenting `key`, whose tag is right if the DH of that key with the responder's
/// ephemeral is `se`.
fn third_presenting(first: &[u8], key: [u8; 32], se: [u8; 32]) -> Vec<u8> {
    let mut state = after_second(first);
    let mut out = state.encrypt_and_hash(&key);
    state.mix_key(&se);
    out.extend_from_slice(&state.encrypt_and_hash(&[]));
    out
}

fn refused_entry(name: &str, error: &str, message: &[u8]) -> Value {
    json!({"name": name, "error": error, "message": hex(message)})
}

fn refused_first(first: &[u8]) -> Vec<Value> {
    let mut high_bit = first.to_vec();
    high_bit[31] |= 0x80;
    let mut list = vec![
        refused_entry("empty", "Malformed", &[]),
        refused_entry("one byte short", "Malformed", &first[..31]),
        refused_entry("a payload follows", "Malformed", &[first, b"x"].concat()),
        refused_entry("the top bit set on a real key", "Malformed", &high_bit),
        refused_entry("p, not reduced", "Malformed", &p_plus(0)),
        refused_entry("p + 1, not reduced", "Malformed", &p_plus(1)),
    ];
    for (index, point) in small_order().iter().enumerate() {
        list.push(refused_entry(
            &format!("an ephemeral key of small order, {index}"),
            "Malformed",
            point,
        ));
    }
    list
}

fn refused_second(first: &[u8], second: &[u8]) -> Vec<Value> {
    let own = public_of(INITIATOR_STATIC);
    let mut high_bit = second.to_vec();
    high_bit[31] |= 0x80;
    let mut list = vec![
        refused_entry("empty", "Malformed", &[]),
        refused_entry("one byte short", "Malformed", &second[..95]),
        refused_entry("a payload follows", "Malformed", &[second, b"x"].concat()),
        refused_entry("its own first message", "Malformed", first),
        refused_entry("the ephemeral key altered", "BadProof", &flipped(second, 0)),
        refused_entry("the top bit set on a real key", "Malformed", &high_bit),
        refused_entry("the static key altered", "BadProof", &flipped(second, 40)),
        refused_entry("the payload tag altered", "BadProof", &flipped(second, 95)),
        refused_entry(
            "a static key of small order, with a right tag",
            "Malformed",
            &second_presenting(first, [0u8; 32], [0u8; 32]),
        ),
        refused_entry(
            "a static key not reduced, with a right tag",
            "Malformed",
            &second_presenting(first, p_plus(1), dh_of(INITIATOR_EPHEMERAL, p_plus(1))),
        ),
        refused_entry(
            "the initiator's own key, with a right tag",
            "Malformed",
            &second_presenting(first, own, dh_of(INITIATOR_EPHEMERAL, own)),
        ),
        refused_entry(
            "the real responder's key, by one who lacks its private key",
            "BadProof",
            &second_presenting(first, public_of(RESPONDER_STATIC), [0x55; 32]),
        ),
    ];
    let mut small_ephemeral = small_order()[1].to_vec();
    small_ephemeral.extend_from_slice(&second[32..]);
    list.push(refused_entry(
        "an ephemeral key of small order",
        "Malformed",
        &small_ephemeral,
    ));
    list
}

fn refused_third(first: &[u8], third: &[u8]) -> Vec<Value> {
    let own = public_of(RESPONDER_STATIC);
    vec![
        refused_entry("empty", "Malformed", &[]),
        refused_entry("one byte short", "Malformed", &third[..63]),
        refused_entry("a payload follows", "Malformed", &[third, b"x"].concat()),
        refused_entry("the static key altered", "BadProof", &flipped(third, 0)),
        refused_entry("the payload tag altered", "BadProof", &flipped(third, 63)),
        refused_entry(
            "a static key of small order, with a right tag",
            "Malformed",
            &third_presenting(first, [0u8; 32], [0u8; 32]),
        ),
        refused_entry(
            "a static key not reduced, with a right tag",
            "Malformed",
            &third_presenting(first, p_plus(1), dh_of(RESPONDER_EPHEMERAL, p_plus(1))),
        ),
        refused_entry(
            "the responder's own key, with a right tag",
            "Malformed",
            &third_presenting(first, own, dh_of(RESPONDER_EPHEMERAL, own)),
        ),
        refused_entry(
            "the real initiator's key, by one who lacks its private key",
            "BadProof",
            &third_presenting(first, public_of(INITIATOR_STATIC), [0x55; 32]),
        ),
    ]
}

fn refused_records(initiator_key: [u8; 32], responder_key: [u8; 32]) -> Vec<Value> {
    let forger = || Forger::new(initiator_key);
    let entry = |name: &str, record: Vec<u8>| json!({"name": name, "record": hex(&record)});
    let full = vec![7u8; 65518];
    let mut flipped_record = forger().message(1, b"data");
    let last = flipped_record.len() - 1;
    flipped_record[last] ^= 1;
    let mut with_trailing = forger().message(1, b"data");
    with_trailing.push(0);
    let mut cut_short = forger().message(1, b"data");
    cut_short.pop();
    let two_messages = {
        let mut f = forger();
        [f.message(1, b"one"), f.message(1, b"two")].concat()
    };
    let close_after_data = {
        let mut f = forger();
        [f.message(1, b"one"), f.message(2, b"")].concat()
    };
    let key_change_then_close = {
        let mut f = forger();
        let change = f.message(3, b"");
        f.rekey();
        [change, f.message(2, b"")].concat()
    };
    let two_key_changes = {
        let mut f = forger();
        let first = f.message(3, b"");
        f.rekey();
        let second = f.message(3, b"");
        f.rekey();
        [first, second, f.message(1, b"data")].concat()
    };
    let key_change_with_contents = {
        let mut f = forger();
        let change = f.message(3, b"x");
        f.rekey();
        [change, f.message(1, b"data")].concat()
    };
    let same_key_after_change = {
        let mut f = forger();
        [f.message(3, b""), f.message(1, b"data")].concat()
    };
    let short_part = {
        let mut f = forger();
        [f.message(4, b"short"), f.message(1, b"data")].concat()
    };
    let part_last = forger().message(4, &full);
    let mut wrong_direction = Forger::new(responder_key);
    vec![
        entry("empty", Vec::new()),
        entry("one byte", vec![0]),
        entry(
            "a length of less than a tag and a type",
            vec![0, 16].into_iter().chain([0; 16]).collect(),
        ),
        entry("a length of zero", vec![0, 0]),
        entry("an altered tag", flipped_record),
        entry("a byte after the message", with_trailing),
        entry("cut short", cut_short),
        entry("type 0", forger().message(0, b"data")),
        entry("type 5", forger().message(5, b"data")),
        entry("type 255", forger().message(255, b"data")),
        entry("no type at all", {
            let sealed = support::aead(&initiator_key, 0, &[], &[]);
            let mut framed = u16::try_from(sealed.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&sealed);
            framed
        }),
        entry("a close with contents", forger().message(2, b"x")),
        entry("two data messages in one record", two_messages),
        entry("a close after data in one record", close_after_data),
        entry("a key change alone", forger().message(3, b"")),
        entry("a key change then a close", key_change_then_close),
        entry("two key changes in a row", two_key_changes),
        entry("a key change with contents", key_change_with_contents),
        entry(
            "a key change and the same key after it",
            same_key_after_change,
        ),
        entry("a part shorter than a whole Noise message", short_part),
        entry("a part as the last message", part_last),
        entry(
            "under the other direction's key",
            wrong_direction.message(1, b"data"),
        ),
    ]
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn build() -> Value {
    let (mut a, mut b) = (
        initiator().initiate().unwrap(),
        responder().respond(None).unwrap(),
    );
    let [first, second, third] = support::messages(&mut a, &mut b).unwrap();
    let (mut near, mut far) = (a.finish().unwrap().session, b.finish().unwrap().session);
    assert_eq!(near.id(), far.id());

    let (initiator_key, responder_key, exporter) = {
        let mut state = after_second(&first);
        state.encrypt_and_hash(&public_of(INITIATOR_STATIC));
        state.mix_key(&dh_of(INITIATOR_STATIC, public_of(RESPONDER_EPHEMERAL)));
        state.encrypt_and_hash(&[]);
        assert_eq!(state.h, *near.id(), "the test's own chain is the code's");
        state.split()
    };

    let mut pair_export = [0u8; 32];
    near.export("EXPORTER-coqui-pair", &mut pair_export)
        .unwrap();
    let mut short_export = [0u8; 16];
    near.export("EXPORTER-coqui-pair", &mut short_export)
        .unwrap();

    let mut records = Vec::new();
    for (from, message) in [
        ("initiator", b"first from the initiator".as_slice()),
        ("responder", b"first from the responder".as_slice()),
        ("initiator", b"".as_slice()),
        ("responder", b"second from the responder".as_slice()),
    ] {
        let (sender, receiver) = if from == "initiator" {
            (&mut near, &mut far)
        } else {
            (&mut far, &mut near)
        };
        let record = sender.seal(message).unwrap();
        assert_eq!(receiver.open(&record).unwrap().as_deref(), Some(message));
        records.push(json!({"from": from, "message": hex(message), "record": hex(&record)}));
    }
    let long = near.seal(&long_message()).unwrap();
    assert_eq!(far.open(&long).unwrap(), Some(long_message()));
    let (close_near, close_far) = (near.close().unwrap(), far.close().unwrap());

    // The same run under a small key limit: the third record starts by changing the key.
    let limited = |method: Noise| method.with_key_limit(KEY_LIMIT);
    let (mut a, mut b) = (
        limited(initiator()).initiate().unwrap(),
        limited(responder()).respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
    let mut limited_near = a.finish().unwrap().session;
    let mut limited_records = Vec::new();
    for index in 0..4u8 {
        let message = vec![index; 100];
        limited_records.push(json!({
            "message": hex(&message),
            "record": hex(&limited_near.seal(&message).unwrap()),
        }));
    }

    // The same run with a binding.
    let (mut a, mut b) = (
        initiator()
            .initiate()
            .unwrap()
            .with_binding(BINDING)
            .unwrap(),
        responder()
            .respond(None)
            .unwrap()
            .with_binding(BINDING)
            .unwrap(),
    );
    let [bound_first, bound_second, bound_third] = support::messages(&mut a, &mut b).unwrap();
    let bound_id = *a.finish().unwrap().session.id();

    json!({
        "_": "Shared by both implementations. Regenerate with: cargo test --test vectors -- --ignored regenerate",
        "protocol": PROTOCOL_NAME,
        "profile": PROFILE,
        "prologue": hex(&prologue(b"")),
        "initiator": side(&identity_of(INITIATOR_STATIC), INITIATOR_STATIC, INITIATOR_EPHEMERAL),
        "responder": side(&identity_of(RESPONDER_STATIC), RESPONDER_STATIC, RESPONDER_EPHEMERAL),
        "messages": [hex(&first), hex(&second), hex(&third)],
        "session": {
            "id": hex(near.id()),
            "initiatorKey": hex(&initiator_key),
            "responderKey": hex(&responder_key),
            "exporter": hex(&exporter),
            "exports": [
                {"label": "EXPORTER-coqui-pair", "length": 32, "bytes": hex(&pair_export)},
                {"label": "EXPORTER-coqui-pair", "length": 16, "bytes": hex(&short_export)},
            ],
        },
        "records": records,
        "longRecord": {"length": LONG_MESSAGE, "modulo": 251, "recordSha256": sha256_hex(&long)},
        "closes": {"initiator": hex(&close_near), "responder": hex(&close_far)},
        "keyLimit": {"limit": KEY_LIMIT, "records": limited_records},
        "binding": {
            "value": hex(BINDING),
            "prologue": hex(&prologue(BINDING)),
            "messages": [hex(&bound_first), hex(&bound_second), hex(&bound_third)],
            "id": hex(&bound_id),
        },
        "refused": {
            "first": refused_first(&first),
            "second": refused_second(&first, &second),
            "third": refused_third(&first, &third),
            "records": refused_records(initiator_key, responder_key),
        },
    })
}

fn unhex(text: &str) -> Vec<u8> {
    HEXLOWER.decode(text.as_bytes()).unwrap()
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/session.json")
}

fn render() -> String {
    serde_json::to_string_pretty(&build()).unwrap() + "\n"
}

#[test]
#[ignore = "writes tests/vectors/session.json; a change there is a change to the wire"]
fn regenerate() {
    std::fs::write(path(), render()).unwrap();
}

fn committed() -> Value {
    serde_json::from_slice(&std::fs::read(path()).unwrap()).unwrap()
}

#[test]
fn the_committed_vectors_are_what_the_code_gives() {
    assert_eq!(std::fs::read_to_string(path()).unwrap(), render());
}

/// The fixed keys and prologue in `snow`, which is another implementation of this protocol.
fn snow_side(initiator_side: bool, binding: &[u8]) -> snow::HandshakeState {
    let (own, ephemeral) = if initiator_side {
        (INITIATOR_STATIC, INITIATOR_EPHEMERAL)
    } else {
        (RESPONDER_STATIC, RESPONDER_EPHEMERAL)
    };
    let prologue = prologue(binding);
    let builder = snow::Builder::new(PROTOCOL_NAME.parse().unwrap())
        .prologue(&prologue)
        .unwrap()
        .local_private_key(&own)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&ephemeral);
    if initiator_side {
        builder.build_initiator().unwrap()
    } else {
        builder.build_responder().unwrap()
    }
}

#[test]
fn snow_reaches_the_same_messages_id_and_records_from_the_same_keys() {
    let vectors = committed();
    for (binding, messages, id) in [
        (&b""[..], &vectors["messages"], &vectors["session"]["id"]),
        (
            BINDING,
            &vectors["binding"]["messages"],
            &vectors["binding"]["id"],
        ),
    ] {
        let (mut a, mut b) = (snow_side(true, binding), snow_side(false, binding));
        let mut buffer = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        for (index, expected) in messages.as_array().unwrap().iter().enumerate() {
            let (from, to) = if index % 2 == 0 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            let written = from.write_message(&[], &mut buffer).unwrap();
            assert_eq!(hex(&buffer[..written]), expected.as_str().unwrap());
            to.read_message(&buffer[..written], &mut scratch).unwrap();
        }
        assert_eq!(hex(a.get_handshake_hash()), id.as_str().unwrap());
    }

    let (mut a, mut b) = (snow_side(true, b""), snow_side(false, b""));
    let mut buffer = [0u8; 70_000];
    let mut scratch = [0u8; 70_000];
    for index in 0..3 {
        let (from, to) = if index % 2 == 0 {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let written = from.write_message(&[], &mut buffer).unwrap();
        to.read_message(&buffer[..written], &mut scratch).unwrap();
    }
    let (mut a, mut b) = (
        a.into_transport_mode().unwrap(),
        b.into_transport_mode().unwrap(),
    );
    for record in vectors["records"].as_array().unwrap() {
        let mut inner = vec![1u8];
        inner.extend_from_slice(&unhex(record["message"].as_str().unwrap()));
        let from = if record["from"] == "initiator" {
            &mut a
        } else {
            &mut b
        };
        let written = from.write_message(&inner, &mut buffer).unwrap();
        // A record is the two-byte length and the Noise message.
        let wire = unhex(record["record"].as_str().unwrap());
        assert_eq!(usize::from(u16::from_be_bytes([wire[0], wire[1]])), written);
        assert_eq!(wire[2..], buffer[..written]);
    }
    // The long record: one whole part, then the rest. Then each direction's close.
    let long = long_message();
    let mut record = Vec::new();
    for (index, chunk) in long.chunks(65518).enumerate() {
        let mut inner = vec![if index == 0 { 4u8 } else { 1u8 }];
        inner.extend_from_slice(chunk);
        let written = a.write_message(&inner, &mut buffer).unwrap();
        record.extend_from_slice(&u16::try_from(written).unwrap().to_be_bytes());
        record.extend_from_slice(&buffer[..written]);
    }
    assert_eq!(
        sha256_hex(&record),
        vectors["longRecord"]["recordSha256"].as_str().unwrap()
    );
    for (transport, close) in [
        (&mut a, &vectors["closes"]["initiator"]),
        (&mut b, &vectors["closes"]["responder"]),
    ] {
        let written = transport.write_message(&[2], &mut buffer).unwrap();
        let wire = unhex(close.as_str().unwrap());
        assert_eq!(wire[2..], buffer[..written]);
    }
}

fn expect_error(error: &Error, name: &str, expected: &str) {
    let matches = match expected {
        "Malformed" => matches!(error, Error::Malformed),
        "BadProof" => matches!(error, Error::BadProof),
        other => panic!("unknown error {other}"),
    };
    assert!(matches, "{name}: {error:?}, not {expected}");
}

/// After a refused message nothing leaves and nothing more is taken.
fn assert_over(handshake: &mut NoiseHandshake, input: &[u8], name: &str) {
    assert!(matches!(handshake.transmit(), Err(Error::State)), "{name}");
    assert!(
        matches!(handshake.receive(input), Err(Error::State)),
        "{name}"
    );
    assert!(!handshake.is_complete(), "{name}");
}

#[test]
fn every_listed_handshake_message_is_refused_at_its_stage() {
    let vectors = committed();
    let first = unhex(vectors["messages"][0].as_str().unwrap());
    let second = unhex(vectors["messages"][1].as_str().unwrap());
    for entry in vectors["refused"]["first"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let mut at = responder().respond(None).unwrap();
        let error = at
            .receive(&unhex(entry["message"].as_str().unwrap()))
            .unwrap_err();
        expect_error(&error, name, entry["error"].as_str().unwrap());
        assert_over(&mut at, &first, name);
    }
    for entry in vectors["refused"]["second"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let mut at = initiator().initiate().unwrap();
        assert_eq!(at.transmit().unwrap().unwrap(), first);
        let error = at
            .receive(&unhex(entry["message"].as_str().unwrap()))
            .unwrap_err();
        expect_error(&error, name, entry["error"].as_str().unwrap());
        assert_over(&mut at, &second, name);
    }
    for entry in vectors["refused"]["third"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let mut at = responder().respond(None).unwrap();
        at.receive(&first).unwrap();
        assert_eq!(at.transmit().unwrap().unwrap(), second);
        let error = at
            .receive(&unhex(entry["message"].as_str().unwrap()))
            .unwrap_err();
        expect_error(&error, name, entry["error"].as_str().unwrap());
        assert_over(&mut at, &first, name);
    }
}

#[test]
fn every_listed_record_is_refused_and_ends_the_session() {
    let vectors = committed();
    for entry in vectors["refused"]["records"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let (mut a, mut b) = (
            initiator().initiate().unwrap(),
            responder().respond(None).unwrap(),
        );
        support::exchange(&mut a, &mut b).unwrap();
        let (mut near, mut far) = (a.finish().unwrap().session, b.finish().unwrap().session);
        let record = unhex(entry["record"].as_str().unwrap());
        assert!(matches!(far.open(&record), Err(Error::Record)), "{name}");
        let genuine = near.seal(b"after it").unwrap();
        assert!(matches!(far.open(&genuine), Err(Error::Record)), "{name}");
        assert!(matches!(far.seal(b"reply"), Err(Error::Record)), "{name}");
        assert!(matches!(far.close(), Err(Error::Record)), "{name}");
        assert!(matches!(far.verify_end(), Err(Error::Record)), "{name}");
    }
}

#[test]
fn a_part_and_a_key_change_in_their_one_shape_are_taken() {
    let vectors = committed();
    let key: [u8; 32] = unhex(vectors["session"]["initiatorKey"].as_str().unwrap())
        .try_into()
        .unwrap();
    let (mut a, mut b) = (
        initiator().initiate().unwrap(),
        responder().respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
    let mut far = b.finish().unwrap().session;
    let whole = vec![7u8; 65518];
    let mut forger = Forger::new(key);
    let mut record = forger.message(4, &whole);
    record.extend_from_slice(&forger.message(3, b""));
    forger.rekey();
    record.extend_from_slice(&forger.message(1, b"tail"));
    let opened = far.open(&record).unwrap().unwrap();
    assert_eq!(opened.len(), whole.len() + 4);
    assert_eq!(&opened[whole.len()..], b"tail");
    assert_eq!(forger.key, rekeyed(&key));
}

#[test]
fn arbitrary_bytes_are_refused_and_never_panic() {
    let vectors = committed();
    let first = unhex(vectors["messages"][0].as_str().unwrap());
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..300 {
        let length = usize::try_from(next() % 200).unwrap();
        let bytes: Vec<u8> = (0..length).map(|_| next().to_le_bytes()[0]).collect();
        let mut at_first = responder().respond(None).unwrap();
        let _ = at_first.receive(&bytes);
        let mut at_second = initiator().initiate().unwrap();
        at_second.transmit().unwrap();
        assert!(at_second.receive(&bytes).is_err(), "round {round}");
        let mut at_third = responder().respond(None).unwrap();
        at_third.receive(&first).unwrap();
        assert!(at_third.receive(&bytes).is_err(), "round {round}");
        let (mut a, mut b) = (
            initiator().initiate().unwrap(),
            responder().respond(None).unwrap(),
        );
        support::exchange(&mut a, &mut b).unwrap();
        let mut far = b.finish().unwrap().session;
        assert!(far.open(&bytes).is_err(), "round {round}");
    }
}
