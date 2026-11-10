//! What a party carrying the connection can do: a reverse proxy that ends TLS, or a relay.
//! Nothing here depends on TLS; the "transport" is whatever the relay chooses to forward.

mod support;

use coqui_peer::{Handshake, Method};
use coqui_peer_noise::{Error, Identity, Noise, Trust};
use support::{exchange, messages, pinned_pair, run, sessions};

#[test]
fn a_plain_relay_connects_only_the_real_parties_and_they_agree_on_one_session() {
    let (client, server, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let seen = messages(&mut a, &mut b).unwrap().concat();
    let (near, far) = (a.finish().unwrap(), b.finish().unwrap());
    assert_eq!(near.peer, server.peer_id());
    assert_eq!(far.peer, client.peer_id());
    let (mut near, mut far) = (near.session, far.session);
    assert_eq!(near.id(), far.id());

    // What the relay saw does not hold the keys that protect what follows.
    let record = near.seal(b"not for the relay").unwrap();
    assert!(!record.windows(4).any(|window| window == b"not "));
    assert_eq!(far.open(&record).unwrap().unwrap(), b"not for the relay");
    let (mut near_export, mut far_export) = ([0u8; 32], [0u8; 32]);
    near.export("label", &mut near_export).unwrap();
    far.export("label", &mut far_export).unwrap();
    assert_eq!(near_export, far_export);
    assert!(!seen.windows(32).any(|window| window == near_export));
}

#[test]
fn a_relay_cannot_inject_a_message_after_the_proof() {
    let (mut near, mut far) = sessions();
    let injected = br#"{"jsonrpc":"2.0","method":"session/prompt"}"#;
    assert!(matches!(far.open(injected), Err(Error::Record)));
    let genuine = near.seal(b"genuine").unwrap();
    assert!(matches!(far.open(&genuine), Err(Error::Record)));
}

#[test]
fn nothing_after_a_bad_record_is_believed_even_at_its_right_place() {
    let (mut near, mut far) = sessions();
    let (first, second) = (near.seal(b"1").unwrap(), near.seal(b"2").unwrap());
    let mut bad = first.clone();
    bad[3] ^= 1;
    assert!(matches!(far.open(&bad), Err(Error::Record)));
    assert!(matches!(far.open(&first), Err(Error::Record)));
    assert!(matches!(far.open(&second), Err(Error::Record)));
}

#[test]
fn a_bad_record_ends_sending_too_split_or_not() {
    let (near, mut far) = sessions();
    assert!(matches!(far.open(b"bad"), Err(Error::Record)));
    assert!(matches!(far.seal(b"x"), Err(Error::Record)));
    assert!(matches!(far.close(), Err(Error::Record)));
    assert!(matches!(far.verify_end(), Err(Error::Record)));

    let (mut sealer, mut opener) = near.split();
    assert!(matches!(opener.open(b"bad"), Err(Error::Record)));
    assert!(matches!(sealer.seal(b"x"), Err(Error::Record)));
    assert!(matches!(sealer.close(), Err(Error::Record)));
}

#[test]
fn a_relay_cannot_swap_replay_reorder_or_reflect_a_record() {
    // Replay.
    let (mut near, mut far) = sessions();
    let record = near.seal(b"once").unwrap();
    assert_eq!(far.open(&record).unwrap().unwrap(), b"once");
    assert!(matches!(far.open(&record), Err(Error::Record)));

    // Reorder: the second first.
    let (mut near, mut far) = sessions();
    let (first, second) = (near.seal(b"1").unwrap(), near.seal(b"2").unwrap());
    assert!(matches!(far.open(&second), Err(Error::Record)));
    drop(first);

    // Reflect: a record sent back to the side that made it, in each direction.
    let (mut near, mut far) = sessions();
    let record = near.seal(b"mine").unwrap();
    assert!(matches!(near.open(&record), Err(Error::Record)));
    let record = far.seal(b"mine").unwrap();
    assert!(matches!(far.open(&record), Err(Error::Record)));

    // Swap a record between two sessions.
    let (mut one, _) = sessions();
    let (_, mut other) = sessions();
    let record = one.seal(b"elsewhere").unwrap();
    assert!(matches!(other.open(&record), Err(Error::Record)));

    // Alter each byte of a record in turn.
    let record = {
        let (mut near, _) = sessions();
        near.seal(b"m").unwrap()
    };
    for index in 0..record.len() {
        let (mut near, mut far) = sessions();
        let mut altered = near.seal(b"m").unwrap();
        assert_eq!(altered.len(), record.len());
        altered[index] ^= 1;
        assert!(matches!(far.open(&altered), Err(Error::Record)), "{index}");
    }
}

#[test]
fn a_relay_cannot_alter_or_swap_a_handshake_message() {
    let (_, _, dialing, listening) = pinned_pair();
    // Every byte of the second and third message is covered by a tag, and a change to the first
    // shows at the tags of the second.
    for (stage, length) in [(0usize, 32usize), (1, 96), (2, 64)] {
        for index in (0..length).step_by(7) {
            let (mut a, mut b) = (
                dialing.initiate().unwrap(),
                listening.respond(None).unwrap(),
            );
            let flip = |current: usize, message: &mut Vec<u8>| {
                if current == stage {
                    message[index] ^= 1;
                }
            };
            let mut first = a.transmit().unwrap().unwrap();
            flip(0, &mut first);
            let outcome = (|| {
                b.receive(&first)?;
                let mut second = b.transmit()?.unwrap();
                flip(1, &mut second);
                a.receive(&second)?;
                let mut third = a.transmit()?.unwrap();
                flip(2, &mut third);
                b.receive(&third)
            })();
            assert!(outcome.is_err(), "message {stage}, byte {index}");
        }
    }
}

#[test]
fn messages_cannot_be_cross_wired_between_two_runs() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a1, mut b1) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let (mut a2, mut b2) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b1.receive(&a1.transmit().unwrap().unwrap()).unwrap();
    b2.receive(&a2.transmit().unwrap().unwrap()).unwrap();
    let second_of_two = b2.transmit().unwrap().unwrap();
    assert!(matches!(a1.receive(&second_of_two), Err(Error::BadProof)));

    // A third message from a run the responder is not in.
    let (mut a3, mut b3) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b3.receive(&a3.transmit().unwrap().unwrap()).unwrap();
    a3.receive(&b3.transmit().unwrap().unwrap()).unwrap();
    let third_of_three = a3.transmit().unwrap().unwrap();
    assert!(matches!(b1.receive(&third_of_three), Err(Error::BadProof)));
}

#[test]
fn a_replayed_first_message_gets_a_fresh_run_whose_third_message_cannot_be_replayed() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let [first, _, third] = messages(&mut a, &mut b).unwrap();
    // The responder draws a fresh ephemeral key, so what was recorded does not complete this run.
    let mut replayed = listening.respond(None).unwrap();
    replayed.receive(&first).unwrap();
    assert!(matches!(replayed.receive(&third), Err(Error::BadProof)));
}

#[test]
fn a_reflected_handshake_message_is_refused() {
    let (_, _, dialing, listening) = pinned_pair();
    // The initiator's first message back at it, as a second message: too short.
    let mut a = dialing.initiate().unwrap();
    let first = a.transmit().unwrap().unwrap();
    assert!(matches!(a.receive(&first), Err(Error::Malformed)));
    // The same with the rest of a real second message: its tags do not hold.
    let mut a = dialing.initiate().unwrap();
    let first = a.transmit().unwrap().unwrap();
    let mut b = listening.respond(None).unwrap();
    b.receive(&first).unwrap();
    let mut second = b.transmit().unwrap().unwrap();
    second[..32].copy_from_slice(&first);
    assert!(matches!(a.receive(&second), Err(Error::BadProof)));
    // The responder's second message back at it, as a third: the length is not a third's.
    let mut b = listening.respond(None).unwrap();
    b.receive(&dialing.initiate().unwrap().transmit().unwrap().unwrap())
        .unwrap();
    let second = b.transmit().unwrap().unwrap();
    assert!(matches!(b.receive(&second), Err(Error::Malformed)));
}

#[test]
fn a_relay_running_a_handshake_of_its_own_fails_a_pin_and_misbinds_nobody() {
    let (client, server, dialing, listening) = pinned_pair();
    let relay = Identity::generate().unwrap();

    // Facing the client, the relay answers as itself. The client pins the server.
    let facing_client = Noise::builder()
        .identity(relay.clone())
        .initiators(Trust::pinned([client.peer_id()]))
        .build()
        .unwrap();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        facing_client.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));

    // Facing the server, the relay dials as itself. The server pins the client.
    let facing_server = Noise::builder()
        .identity(relay)
        .responders(Trust::pinned([server.peer_id()]))
        .build()
        .unwrap();
    let (mut a, mut b) = (
        facing_server.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
}

#[test]
fn a_client_that_trusts_a_relay_and_a_server_that_trusts_it_share_no_session_through_it() {
    // Unknown key share: the two ends each believe they talk to the relay, which both trust, and the
    // relay wants the server to take the client's messages as the relay's own. Forwarding records
    // between its two sessions fails, since each pair of ends has its own keys.
    let (client, server, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let client_side = Noise::builder()
        .identity(client.clone())
        .responders(Trust::pinned([relay.peer_id()]))
        .build()
        .unwrap();
    let relay_as_responder = Noise::builder()
        .identity(relay.clone())
        .initiators(Trust::pinned([client.peer_id()]))
        .build()
        .unwrap();
    let relay_as_initiator = Noise::builder()
        .identity(relay.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build()
        .unwrap();
    let server_side = Noise::builder()
        .identity(server)
        .initiators(Trust::pinned([relay.peer_id()]))
        .build()
        .unwrap();
    let (near, relay_near) = run(&client_side, &relay_as_responder).unwrap();
    let (relay_far, far) = run(&relay_as_initiator, &server_side).unwrap();
    assert_eq!(near.peer, relay.peer_id());
    assert_eq!(far.peer, relay.peer_id());
    assert_ne!(near.session.id(), far.session.id());
    let (mut near, mut far) = (near.session, far.session);
    let forwarded = near.seal(b"as the client").unwrap();
    assert!(matches!(far.open(&forwarded), Err(Error::Record)));
    drop((relay_near, relay_far));

    // And a relay swapping one static key on the way sees the tag fail: it has no key for that.
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    let mut second = b.transmit().unwrap().unwrap();
    second[32..64].fill(0x42);
    assert!(matches!(a.receive(&second), Err(Error::BadProof)));
}

#[test]
fn an_outer_binding_is_optional_and_refuses_two_different_channels() {
    let (_, _, dialing, listening) = pinned_pair();
    let bind = |binding: &[u8]| {
        (
            dialing.initiate().unwrap().bind(binding).unwrap(),
            listening.respond(None).unwrap().bind(binding).unwrap(),
        )
    };
    let (mut a, mut b) = bind(b"the same channel");
    exchange(&mut a, &mut b).unwrap();
    let bound_id = *a.finish().unwrap().session.id();

    // A relay ending TLS on both sides gives each end another value.
    let mut a = dialing.initiate().unwrap().bind(b"client side").unwrap();
    let mut b = listening
        .respond(None)
        .unwrap()
        .bind(b"server side")
        .unwrap();
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::BadProof)));

    // One end with a binding, one without: a proxy that ends TLS for one side only.
    let mut a = dialing.initiate().unwrap().bind(b"client side").unwrap();
    let mut b = listening.respond(None).unwrap();
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::BadProof)));

    // With none, through a reverse proxy, both ends agree and the id differs.
    let (near, _far) = run(&dialing, &listening).unwrap();
    assert_ne!(*near.session.id(), bound_id);
}

#[test]
fn a_binding_set_after_the_prologue_is_fixed_is_refused() {
    let (_, _, dialing, listening) = pinned_pair();
    let mut a = dialing.initiate().unwrap();
    let first = a.transmit().unwrap().unwrap();
    assert!(matches!(a.bind(b"late"), Err(Error::State)));
    let mut b = listening.respond(None).unwrap();
    b.receive(&first).unwrap();
    assert!(matches!(b.bind(b"late"), Err(Error::State)));
}

#[test]
fn an_export_is_the_same_at_both_ends_and_a_relay_cannot_derive_it_from_the_id() {
    let (near, far) = sessions();
    let (mut at_near, mut at_far) = ([0u8; 32], [0u8; 32]);
    near.export("EXPORTER-test", &mut at_near).unwrap();
    far.export("EXPORTER-test", &mut at_far).unwrap();
    assert_eq!(at_near, at_far);
    assert_ne!(&at_near, near.id());
}

#[test]
fn exports_of_one_label_and_two_lengths_are_unrelated() {
    let (near, _) = sessions();
    let (mut short, mut long, mut other) = ([0u8; 16], [0u8; 32], [0u8; 32]);
    near.export("label", &mut short).unwrap();
    near.export("label", &mut long).unwrap();
    near.export("other", &mut other).unwrap();
    assert_ne!(short[..], long[..16]);
    assert_ne!(long, other);
    let mut too_long = vec![0u8; 8161];
    assert!(matches!(
        near.export("label", &mut too_long),
        Err(Error::TooLong)
    ));
    let mut most = vec![0u8; 8160];
    near.export("label", &mut most).unwrap();
}
