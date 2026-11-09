//! The method through `coqui_peer`'s traits: its two roles, its trust, and its place in a store.

mod support;

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use coqui_peer::{Framing, Handshake, MessageTransport, Method, drive_messages};
use coqui_peer_noise::{
    DEFAULT_KEY_LIMIT, Error, Identity, MAX_HANDSHAKE_MESSAGE, METHOD, Noise, Trust, TrustStore,
};
use support::{exchange, messages, pinned_pair, run, scripted};

struct Pipe(Sender<Vec<u8>>, Receiver<Vec<u8>>);

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> std::io::Result<()> {
        self.0
            .send(message.to_vec())
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }

    fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        self.1
            .recv()
            .map_err(|_| std::io::ErrorKind::UnexpectedEof.into())
    }
}

fn store() -> (tempfile::TempDir, TrustStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn both_roles_prove_each_other_and_reach_one_session() {
    let (client, server, dialing, listening) = pinned_pair();
    assert_eq!(dialing.name(), METHOD);
    let (near, far) = run(&dialing, &listening).unwrap();
    assert_eq!(near.peer, server.peer_id());
    assert_eq!(far.peer, client.peer_id());
    assert_eq!(near.key.unwrap(), server.key_material());
    assert_eq!(far.key.unwrap(), client.key_material());
    let (mut near, mut far) = (near.session, far.session);
    assert_eq!(near.id(), far.id());
    let there = near.seal(b"there").unwrap();
    assert_eq!(far.open(&there).unwrap().unwrap(), b"there");
    let back = far.seal(b"back").unwrap();
    assert_eq!(near.open(&back).unwrap().unwrap(), b"back");
}

#[test]
fn it_runs_over_coqui_peers_message_driver_and_says_it_is_message_framed() {
    let (client, server, dialing, listening) = pinned_pair();
    assert_eq!(dialing.initiate().unwrap().framing(), Framing::Message);
    let ((to_far, from_near), (to_near, from_far)) = (channel(), channel());
    let serving = thread::spawn(move || {
        let handshake = listening.respond(None).unwrap();
        drive_messages(handshake, &mut Pipe(to_near, from_near)).unwrap()
    });
    let near = drive_messages(dialing.initiate().unwrap(), &mut Pipe(to_far, from_far)).unwrap();
    let far = serving.join().unwrap();
    assert_eq!(near.peer, server.peer_id());
    assert_eq!(far.peer, client.peer_id());
}

#[test]
fn the_messages_have_the_lengths_the_pattern_gives() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let [first, second, third] = messages(&mut a, &mut b).unwrap();
    assert_eq!(first.len(), 32);
    assert_eq!(second.len(), MAX_HANDSHAKE_MESSAGE);
    assert_eq!(third.len(), 64);
    assert!(a.is_complete() && b.is_complete());
    assert!(a.transmit().unwrap().is_none());
}

#[test]
fn neither_static_key_goes_in_the_clear() {
    let (client, server, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let sent = messages(&mut a, &mut b).unwrap().concat();
    for key in [client.public_key(), server.public_key()] {
        assert!(!sent.windows(32).any(|window| window == key));
    }
}

#[test]
fn a_role_with_no_trust_configured_is_unsupported() {
    let method = Noise::builder(Identity::generate().unwrap()).build();
    assert!(matches!(method.initiate(), Err(Error::Unsupported)));
    assert!(matches!(method.respond(None), Err(Error::Unsupported)));
}

#[test]
fn a_responder_refuses_an_initiator_it_does_not_pin_only_once_that_peer_proved_its_key() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let stranger = Identity::generate().unwrap();
    let dialing = Noise::builder(client)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([stranger.peer_id()]))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let first = a.transmit().unwrap().unwrap();
    b.receive(&first).unwrap();
    let second = b.transmit().unwrap().unwrap();
    a.receive(&second).unwrap();
    let third = a.transmit().unwrap().unwrap();
    assert!(matches!(b.receive(&third), Err(Error::Untrusted)));
    assert!(matches!(b.transmit(), Err(Error::State)));
}

#[test]
fn an_initiator_refuses_a_responder_it_does_not_pin_and_sends_it_nothing_more() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let stranger = Identity::generate().unwrap();
    let dialing = Noise::builder(client.clone())
        .responders(Trust::pinned([stranger.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    let second = b.transmit().unwrap().unwrap();
    assert!(matches!(a.receive(&second), Err(Error::Untrusted)));
    // Its static key, the third message, never left.
    assert!(matches!(a.transmit(), Err(Error::State)));
}

#[test]
fn an_empty_pin_set_admits_nobody() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server).initiators(Trust::pinned([])).build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
}

#[test]
fn a_pin_of_another_digest_matches_nothing() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let sha512 = coqui_peer::Digest::Sha512.of(server.spki_der());
    let dialing = Noise::builder(client)
        .responders(Trust::pinned([sha512]))
        .build();
    let listening = Noise::builder(server).initiators(Trust::pinned([])).build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
}

#[test]
fn finish_before_the_end_is_refused() {
    let (_, _, dialing, listening) = pinned_pair();
    assert!(matches!(
        dialing.initiate().unwrap().finish(),
        Err(Error::State)
    ));
    let mut a = dialing.initiate().unwrap();
    let mut b = listening.respond(None).unwrap();
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    a.receive(&b.transmit().unwrap().unwrap()).unwrap();
    assert!(!a.is_complete(), "the third message waits to be sent");
    assert!(matches!(a.finish(), Err(Error::State)));
    assert!(matches!(b.finish(), Err(Error::State)));
}

#[test]
fn messages_out_of_their_place_are_refused() {
    let (_, _, dialing, listening) = pinned_pair();
    let mut a = dialing.initiate().unwrap();
    assert!(
        matches!(a.receive(&[0; 96]), Err(Error::State)),
        "before the first message went"
    );
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
    assert!(matches!(b.receive(&[0; 64]), Err(Error::State)));
    assert!(matches!(a.receive(&[0; 96]), Err(Error::State)));
}

#[test]
fn a_peer_dialling_itself_is_refused() {
    let identity = Identity::generate().unwrap();
    let trust = Trust::pinned([identity.peer_id()]);
    let dialing = Noise::builder(identity.clone())
        .responders(trust.clone())
        .build();
    let listening = Noise::builder(identity).initiators(trust).build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Malformed)));
}

#[test]
fn a_failing_source_gives_an_error_and_not_a_panic() {
    let failing = coqui_peer_noise::Random::from_fn(|_| Err(coqui_peer::Error::Random));
    let (_, _, broken, listening) = support::pinned_pair_with(failing);
    assert!(matches!(broken.initiate(), Err(Error::Random)));
    let mut b = listening.respond(None).unwrap();
    let (_, _, dialing, _) = support::pinned_pair();
    let first = dialing.initiate().unwrap().transmit().unwrap().unwrap();
    assert!(matches!(b.receive(&first), Err(Error::Random)));
}

#[test]
fn looser_settings_are_reported() {
    let identity = Identity::generate().unwrap();
    let configured =
        |build: &dyn Fn(coqui_peer_noise::NoiseBuilder) -> coqui_peer_noise::NoiseBuilder| {
            build(Noise::builder(identity.clone())).build()
        };
    assert!(configured(&|builder| builder).non_defaults().is_empty());
    let names = |method: Noise| {
        method
            .non_defaults()
            .into_iter()
            .map(|non_default| non_default.setting)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(configured(
            &|builder| builder.key_limit(DEFAULT_KEY_LIMIT + 1)
        )),
        ["key_limit"]
    );
    assert_eq!(
        names(configured(&|builder| builder.rekey(false))),
        ["rekey"]
    );
    assert_eq!(
        names(configured(&|builder| builder.random(scripted(&[])))),
        ["random"]
    );
}

#[test]
fn nothing_secret_is_in_a_debug_form() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    exchange(&mut a, &mut b).unwrap();
    assert!(format!("{a:?}").contains("complete"));
    assert!(format!("{dialing:?}").contains("Noise"));
    let session = a.finish().unwrap().session;
    assert_eq!(format!("{session:?}"), "Session { .. }");
    let (sealer, opener) = session.split();
    assert_eq!(format!("{sealer:?} {opener:?}"), "Sealer Opener");
}

#[test]
fn a_store_admits_an_accepted_key_and_records_a_proved_stranger_as_waiting() {
    let (_dir, store) = store();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();
    let source: SocketAddr = "192.0.2.1:9".parse().unwrap();

    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(Some(source)).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, client.peer_id());
    assert_eq!(
        store.waiting_key(&client.peer_id()).unwrap(),
        client.key_material()
    );

    store.accept(&client.peer_id()).unwrap();
    let (near, far) = run(&dialing, &listening).unwrap();
    assert_eq!(far.peer, client.peer_id());
    drop(near);

    assert!(store.remove(&client.peer_id()).unwrap());
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
}

#[test]
fn a_peer_that_proves_nothing_is_not_recorded_in_a_store() {
    let (_dir, store) = store();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    a.receive(&b.transmit().unwrap().unwrap()).unwrap();
    let mut third = a.transmit().unwrap().unwrap();
    // The key inside is real and the tag after it is not: this peer shows the key and no proof.
    let last = third.len() - 1;
    third[last] ^= 1;
    assert!(matches!(b.receive(&third), Err(Error::BadProof)));
    assert!(store.waiting().unwrap().is_empty());
}

#[test]
fn an_initiator_keeping_a_store_records_nobody() {
    let (_dir, store) = store();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client.clone())
        .responders(Trust::Store(store.clone()))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
    assert!(store.waiting().unwrap().is_empty());
}

#[test]
fn a_store_key_of_another_method_with_the_same_bytes_is_not_this_key() {
    let (_dir, store) = store();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let mut material = client.key_material();
    material.method = "webcrypto".to_owned();
    store.accept_key(&material).unwrap();
    let dialing = Noise::builder(client)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::Store(store))
        .build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
}

#[test]
fn the_proved_successor_of_an_accepted_key_is_promoted() {
    let (_dir, store) = store();
    let (old, new, server) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    store.accept_key(&old.key_material()).unwrap();
    store
        .announce_successor(&old.peer_id(), &new.key_material())
        .unwrap();
    let dialing = Noise::builder(new.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();
    run(&dialing, &listening).unwrap();
    assert!(store.is_accepted(&new.peer_id()));
}

#[test]
fn a_noise_key_can_succeed_an_accepted_key_of_another_method() {
    let (_dir, store) = store();
    let (noise_key, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let old = coqui_peer::KeyMaterial {
        method: "webcrypto".to_owned(),
        label: "PUBLIC KEY".to_owned(),
        bytes: vec![0x42; 91],
    };
    store.accept_key(&old).unwrap();
    store
        .announce_successor(&old.id(), &noise_key.key_material())
        .unwrap();
    let dialing = Noise::builder(noise_key.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();
    run(&dialing, &listening).unwrap();
    assert_eq!(
        store.accepted_key(&noise_key.peer_id()).unwrap(),
        noise_key.key_material()
    );
}

#[test]
fn a_responder_that_did_not_prove_its_key_gets_no_third_message() {
    // It knows the initiator's first message and sends the real server's key, with no private key.
    let (_, server, dialing, _) = pinned_pair();
    let mut at_client = dialing.initiate().unwrap();
    let first = at_client.transmit().unwrap().unwrap();
    let mut forged = first.clone();
    forged.extend_from_slice(server.public_key());
    forged.extend_from_slice(&[0u8; 32]);
    assert_eq!(forged.len(), MAX_HANDSHAKE_MESSAGE);
    assert!(at_client.receive(&forged).is_err());
    assert!(matches!(at_client.transmit(), Err(Error::State)));
}
