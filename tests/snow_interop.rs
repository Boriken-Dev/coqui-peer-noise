//! This crate against `snow`, another implementation of the same Noise protocol, in both roles.

mod support;

use coqui_peer::{Handshake, Method};
use coqui_peer_noise::{Identity, Noise, PROFILE, PROTOCOL_NAME, Trust};
use support::identity_of;

const SNOW_KEY: [u8; 32] = [0x66; 32];
const LEN: usize = 70_000;

fn prologue() -> Vec<u8> {
    let mut out = Vec::new();
    for field in [PROFILE.as_bytes(), b"ordinary", b""] {
        out.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn snow_builder<'a>(prologue: &'a [u8], key: &'a [u8; 32]) -> snow::Builder<'a> {
    snow::Builder::new(PROTOCOL_NAME.parse().unwrap())
        .prologue(prologue)
        .unwrap()
        .local_private_key(key)
        .unwrap()
}

/// A record holding one Noise message from `snow`, as this crate frames them.
fn framed(transport: &mut snow::TransportState, inner: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; LEN];
    let written = transport.write_message(inner, &mut buffer).unwrap();
    let mut out = u16::try_from(written).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(&buffer[..written]);
    out
}

/// The Noise message of a record holding one, opened by `snow`.
fn opened(transport: &mut snow::TransportState, record: &[u8]) -> Vec<u8> {
    let length = usize::from(u16::from_be_bytes([record[0], record[1]]));
    assert_eq!(record.len(), 2 + length, "one Noise message");
    let mut buffer = vec![0u8; LEN];
    let read = transport.read_message(&record[2..], &mut buffer).unwrap();
    buffer.truncate(read);
    buffer
}

#[test]
fn this_crate_as_initiator_with_a_snow_responder() {
    let client = Identity::generate().unwrap();
    let snow_id = identity_of(SNOW_KEY);
    let mut at_us = Noise::builder()
        .identity(client)
        .responders(Trust::pinned([snow_id.peer_id()]))
        .build()
        .unwrap()
        .initiate()
        .unwrap();
    let prologue = prologue();
    let mut at_snow = snow_builder(&prologue, &SNOW_KEY)
        .build_responder()
        .unwrap();
    let (mut buffer, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);

    at_snow
        .read_message(&at_us.transmit().unwrap().unwrap(), &mut scratch)
        .unwrap();
    let written = at_snow.write_message(&[], &mut buffer).unwrap();
    at_us.receive(&buffer[..written]).unwrap();
    at_snow
        .read_message(&at_us.transmit().unwrap().unwrap(), &mut scratch)
        .unwrap();
    assert!(at_snow.is_handshake_finished());

    let established = at_us.finish().unwrap();
    assert_eq!(established.peer, snow_id.peer_id());
    let mut session = established.session;
    assert_eq!(session.id()[..], *at_snow.get_handshake_hash());
    let mut transport = at_snow.into_transport_mode().unwrap();

    let inner = opened(&mut transport, &session.seal(b"to snow").unwrap());
    assert_eq!(inner, [b"\x01".as_slice(), b"to snow"].concat());
    let reply = framed(&mut transport, b"\x01from snow");
    assert_eq!(session.open(&reply).unwrap().unwrap(), b"from snow");
    assert_eq!(session.open(&framed(&mut transport, &[2])).unwrap(), None);
    session.verify_end().unwrap();
    assert_eq!(opened(&mut transport, &session.close().unwrap()), [2]);
}

#[test]
fn this_crate_as_responder_with_a_snow_initiator_changing_keys_as_snow_does() {
    let server = Identity::generate().unwrap();
    let snow_id = identity_of(SNOW_KEY);
    let mut at_us = Noise::builder()
        .identity(server.clone())
        .initiators(Trust::pinned([snow_id.peer_id()]))
        .build()
        .unwrap()
        .respond(None)
        .unwrap();
    let prologue = prologue();
    let mut at_snow = snow_builder(&prologue, &SNOW_KEY)
        .build_initiator()
        .unwrap();
    let (mut buffer, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);

    let written = at_snow.write_message(&[], &mut buffer).unwrap();
    at_us.receive(&buffer[..written]).unwrap();
    at_snow
        .read_message(&at_us.transmit().unwrap().unwrap(), &mut scratch)
        .unwrap();
    let written = at_snow.write_message(&[], &mut buffer).unwrap();
    at_us.receive(&buffer[..written]).unwrap();
    assert!(at_us.is_complete());

    let established = at_us.finish().unwrap();
    assert_eq!(established.peer, snow_id.peer_id());
    let mut session = established.session;
    assert_eq!(session.id()[..], *at_snow.get_handshake_hash());
    let mut transport = at_snow.into_transport_mode().unwrap();

    // A key change followed by data under snow's own REKEY, then the same in the other direction.
    let mut record = framed(&mut transport, &[3]);
    transport.rekey_outgoing();
    record.extend_from_slice(&framed(&mut transport, b"\x01after snow rekeyed"));
    assert_eq!(
        session.open(&record).unwrap().unwrap(),
        b"after snow rekeyed"
    );
    assert_eq!(
        session
            .open(&framed(&mut transport, b"\x01and it stays"))
            .unwrap()
            .unwrap(),
        b"and it stays"
    );
    assert_eq!(
        opened(&mut transport, &session.seal(b"back").unwrap()),
        b"\x01back"
    );
}

#[test]
fn a_key_change_from_this_crate_is_what_snow_rekey_incoming_expects() {
    let client = Identity::generate().unwrap();
    let snow_id = identity_of(SNOW_KEY);
    let method = Noise::builder()
        .identity(client)
        .responders(Trust::pinned([snow_id.peer_id()]))
        .key_limit(298)
        .build()
        .unwrap();
    let mut at_us = method.initiate().unwrap();
    let prologue = prologue();
    let mut at_snow = snow_builder(&prologue, &SNOW_KEY)
        .build_responder()
        .unwrap();
    let (mut buffer, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);
    at_snow
        .read_message(&at_us.transmit().unwrap().unwrap(), &mut scratch)
        .unwrap();
    let written = at_snow.write_message(&[], &mut buffer).unwrap();
    at_us.receive(&buffer[..written]).unwrap();
    at_snow
        .read_message(&at_us.transmit().unwrap().unwrap(), &mut scratch)
        .unwrap();
    let mut session = at_us.finish().unwrap().session;
    let mut transport = at_snow.into_transport_mode().unwrap();

    for index in 0..2u8 {
        let inner = opened(&mut transport, &session.seal(&[index; 100]).unwrap());
        assert_eq!(inner[1..], [index; 100]);
    }
    let record = session.seal(&[2; 100]).unwrap();
    // The third crosses the limit: a key change, then the data under the next key.
    let length = usize::from(u16::from_be_bytes([record[0], record[1]]));
    assert_eq!(length, 17);
    let mut plain = vec![0u8; LEN];
    let read = transport.read_message(&record[2..19], &mut plain).unwrap();
    assert_eq!(plain[..read], [3]);
    transport.rekey_incoming();
    let inner = opened(&mut transport, &record[19..]);
    assert_eq!(inner[1..], [2; 100]);
}
