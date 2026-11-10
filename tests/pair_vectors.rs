//! Shared vectors of a whole PIN pairing, which the JavaScript module reproduces byte for byte: fixed
//! keys and fixed draws give fixed records. `tests/vectors/pairing.json` regenerates with
//! `cargo test --features pin --test pair_vectors -- --ignored regenerate`.

mod support;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::{fs, io, thread};

use coqui_peer::pair::{
    CodeAlphabet, Pairing, PairingDesk, PairingJoiner, PairingResponder, Pin, PinRole,
};
use coqui_peer::{Handshake, Method, Random, ReadTimeout};
use coqui_peer_noise::{
    CurrentReadTimeout, MessageTransport, PairDial, PairingMethod, PairingSession, TrustStore,
};
use serde_json::{Value, json};
use support::{identity_of, pkcs8, public_of, scripted};

const JOINER_STATIC: [u8; 32] = [0x21; 32];
const JOINER_EPHEMERAL: [u8; 32] = [0x22; 32];
const RESPONDER_STATIC: [u8; 32] = [0x31; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x32; 32];
const JOINER_PAKE: [u8; 64] = [0x23; 64];
const RESPONDER_PAKE: [u8; 64] = [0x33; 64];
const PIN_DIGITS: [u8; 6] = [4, 9, 3, 0, 2, 7];
const PIN: &str = "493027";
const WRONG_PIN: &str = "493028";

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// A source that hands out exactly `bytes`, however they are asked for.
fn bytes_of(bytes: Vec<u8>) -> Random {
    let queue = Arc::new(Mutex::new(VecDeque::from(bytes)));
    Random::from_fn(move |out| {
        let mut queue = queue.lock().unwrap();
        for byte in out.iter_mut() {
            *byte = queue.pop_front().expect("a scripted draw");
        }
        Ok(())
    })
}

/// What the desk draws: one big-endian word per digit of the PIN, then the responder's PAKE scalar.
fn desk_draws() -> Vec<u8> {
    let mut draws = Vec::new();
    for digit in PIN_DIGITS {
        draws.extend_from_slice(&u32::from(digit).to_be_bytes());
    }
    draws.extend_from_slice(&RESPONDER_PAKE);
    draws
}

fn joining(pin: &str) -> Pairing {
    Pairing::pin(
        Pin::parse(&CodeAlphabet::pin(), pin).unwrap(),
        PinRole::Typed,
    )
    .random(bytes_of(JOINER_PAKE.to_vec()))
}

fn sessions() -> (PairingSession, PairingSession, [Vec<u8>; 3]) {
    let near = PairingMethod::builder()
        .identity(identity_of(JOINER_STATIC))
        .random(scripted(&[JOINER_EPHEMERAL]))
        .build()
        .unwrap();
    let far = PairingMethod::builder()
        .identity(identity_of(RESPONDER_STATIC))
        .random(scripted(&[RESPONDER_EPHEMERAL]))
        .build()
        .unwrap();
    let (mut a, mut b) = (near.initiate().unwrap(), far.respond(None).unwrap());
    let first = a.transmit().unwrap().unwrap();
    b.receive(&first).unwrap();
    let second = b.transmit().unwrap().unwrap();
    a.receive(&second).unwrap();
    let third = a.transmit().unwrap().unwrap();
    b.receive(&third).unwrap();
    (
        a.finish().unwrap().session,
        b.finish().unwrap().session,
        [first, second, third],
    )
}

/// A pipe's end that also keeps what it sends.
struct Kept {
    out: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl MessageTransport for &mut Kept {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.sent.push(message.to_vec());
        self.out
            .send(message.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.inbox
            .recv()
            .map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

impl ReadTimeout for &mut Kept {
    fn set_read_timeout(&self, _: Option<core::time::Duration>) -> io::Result<()> {
        Ok(())
    }
}

impl CurrentReadTimeout for &mut Kept {
    fn current_read_timeout(&self) -> Option<core::time::Duration> {
        None
    }
}

fn desk() -> (PairingDesk, TrustStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let desk = PairingDesk::new(bytes_of(desk_draws()));
    assert_eq!(desk.show_pin().unwrap().pin.as_str(), PIN);
    (desk, store, dir)
}

/// The plain messages, in order, by the sans-IO exchange on the same keys and draws.
fn plain(pin: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (near, far, _) = sessions();
    let (desk, store, _dir) = desk();
    let mut joiner: PairingJoiner = joining(pin).join(near.pair_channel().unwrap()).unwrap();
    let mut responder = PairingResponder::new(far.pair_channel().unwrap(), &store, &desk, None);
    let (mut from_joiner, mut from_responder) = (Vec::new(), Vec::new());
    loop {
        let mut moved = false;
        while let Some(message) = joiner.transmit() {
            from_joiner.push(message.clone());
            moved = true;
            if responder.receive(&message).is_err() {
                break;
            }
        }
        while let Some(message) = responder.transmit() {
            from_responder.push(message.clone());
            moved = true;
            if joiner.receive(&message).is_err() {
                break;
            }
        }
        if !moved {
            return (from_joiner, from_responder);
        }
    }
}

/// The records of one run, as each driver sends them.
fn records(pin: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (near, far, _) = sessions();
    let (desk, store, dir) = desk();
    let (to_joiner, joiner_inbox) = mpsc::channel();
    let (to_responder, responder_inbox) = mpsc::channel();
    let serving = thread::spawn(move || {
        let mut kept = Kept {
            out: to_joiner,
            inbox: responder_inbox,
            sent: Vec::new(),
        };
        let _ = far.respond(&store, &desk, None, &mut &mut kept);
        kept.sent
    });
    let mut kept = Kept {
        out: to_responder,
        inbox: joiner_inbox,
        sent: Vec::new(),
    };
    let mut transport = &mut kept;
    let _ = near
        .join(joining(pin), &mut transport)
        .and_then(PairDial::finish);
    let from_joiner = kept.sent.clone();
    drop(kept);
    let from_responder = serving.join().unwrap();
    drop(dir);
    (from_joiner, from_responder)
}

/// Pairs the driver's records with the plain messages; a close record has no plain message.
fn list(plain: &[Vec<u8>], records: &[Vec<u8>]) -> Vec<Value> {
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            json!({
                "plain": plain.get(index).map_or_else(String::new, |message| hex(message)),
                "record": hex(record),
            })
        })
        .collect()
}

fn run(pin: &str) -> Value {
    let (plain_joiner, plain_responder) = plain(pin);
    let (from_joiner, from_responder) = records(pin);
    json!({
        "pin": pin,
        "joiner": list(&plain_joiner, &from_joiner),
        "responder": list(&plain_responder, &from_responder),
    })
}

fn side(raw: [u8; 32], ephemeral: [u8; 32]) -> Value {
    json!({
        "pkcs8": hex(&pkcs8(raw)),
        "peerId": identity_of(raw).peer_id().to_string(),
        "publicKey": hex(identity_of(raw).public_key()),
        "ephemeralPkcs8": hex(&pkcs8(ephemeral)),
        "ephemeralPublic": hex(&public_of(ephemeral)),
    })
}

fn build() -> Value {
    let (near, far, handshake) = sessions();
    assert_eq!(near.id(), far.id());
    let channel = near.pair_channel().unwrap();
    json!({
        "description": "A whole PIN pairing on a Noise session. Regenerate with `cargo test --features pin --test pair_vectors -- --ignored regenerate`; a change here is a change to the wire.",
        "joiner": side(JOINER_STATIC, JOINER_EPHEMERAL),
        "responder": side(RESPONDER_STATIC, RESPONDER_EPHEMERAL),
        "joinerPakeRandom": hex(&JOINER_PAKE),
        "deskRandom": hex(&desk_draws()),
        "handshake": handshake.iter().map(|message| hex(message)).collect::<Vec<_>>(),
        "id": hex(near.id()),
        "binding": hex(channel.binding.as_deref().unwrap()),
        "right": run(PIN),
        "wrong": run(WRONG_PIN),
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/pairing.json")
}

fn render() -> String {
    format!("{}\n", serde_json::to_string_pretty(&build()).unwrap())
}

#[test]
#[ignore = "writes tests/vectors/pairing.json; a change there is a change to the wire"]
fn regenerate() {
    fs::write(path(), render()).unwrap();
}

#[test]
fn the_committed_vectors_are_what_the_code_gives() {
    let committed: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(committed, build());
}

#[test]
fn the_right_run_ends_in_both_closes_and_the_wrong_run_in_a_refusal() {
    let vectors = build();
    let right = &vectors["right"];
    // Hello, PAKE, confirmation and a close; ready, reply, done and a close.
    assert_eq!(right["joiner"].as_array().unwrap().len(), 4);
    assert_eq!(right["responder"].as_array().unwrap().len(), 4);
    assert_eq!(right["joiner"][3]["plain"], "");
    assert_eq!(right["responder"][3]["plain"], "");
    let wrong = &vectors["wrong"];
    // Hello, PAKE and the refusal `01 08 01`, for the wrong code; ready and reply.
    assert_eq!(wrong["joiner"].as_array().unwrap().len(), 3);
    assert_eq!(wrong["joiner"][2]["plain"], "010801");
    assert_eq!(wrong["responder"].as_array().unwrap().len(), 2);
}
