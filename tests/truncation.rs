//! A relay can end a stream at any record boundary, and Noise's transport has no end marker. The close
//! record is what makes that visible. Also the limits on what a key carries, and key changes.

mod support;

use coqui_peer_noise::{DEFAULT_KEY_LIMIT, Error, Identity, Noise, Session, Trust};
use support::{Forger, run, sessions};

/// Sessions under the same settings at both ends.
fn limited(limit: u64, rekey: bool) -> (Session, Session) {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .key_limit(limit)
        .rekey(rekey)
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .key_limit(limit)
        .rekey(rekey)
        .build();
    let (near, far) = run(&dialing, &listening).unwrap();
    (near.session, far.session)
}

#[test]
fn a_relay_cutting_at_each_boundary_is_reported_as_truncation() {
    const MESSAGES: usize = 4;
    for delivered in 0..=MESSAGES {
        let (mut near, mut far) = sessions();
        let mut records: Vec<Vec<u8>> = (0..MESSAGES)
            .map(|index| near.seal(&[u8::try_from(index).unwrap()]).unwrap())
            .collect();
        records.push(near.close().unwrap());
        for (index, record) in records.iter().take(delivered).enumerate() {
            assert_eq!(
                far.open(record).unwrap(),
                Some(vec![u8::try_from(index).unwrap()])
            );
        }
        assert!(
            matches!(far.verify_end(), Err(Error::Truncated)),
            "cut after {delivered} records"
        );
    }
}

#[test]
fn a_stream_ending_with_its_close_record_is_complete() {
    let (mut near, mut far) = sessions();
    assert_eq!(far.open(&near.seal(b"m").unwrap()).unwrap().unwrap(), b"m");
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn each_direction_closes_on_its_own() {
    let (mut near, mut far) = sessions();
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    assert!(matches!(near.seal(b"x"), Err(Error::Closed)));
    assert!(matches!(near.close(), Err(Error::Closed)));
    // The other way still goes.
    let record = far.seal(b"still here").unwrap();
    assert_eq!(near.open(&record).unwrap().unwrap(), b"still here");
    assert!(matches!(near.verify_end(), Err(Error::Truncated)));
    assert_eq!(near.open(&far.close().unwrap()).unwrap(), None);
    near.verify_end().unwrap();
}

#[test]
fn a_record_after_the_peers_close_is_refused_and_ends_the_session() {
    let (mut near, mut far) = sessions();
    let close = near.close().unwrap();
    assert_eq!(far.open(&close).unwrap(), None);
    assert!(matches!(far.open(&close), Err(Error::Record)));
    assert!(matches!(far.seal(b"x"), Err(Error::Record)));
    assert!(matches!(far.verify_end(), Err(Error::Record)));
}

#[test]
fn a_relay_cannot_make_a_close_record() {
    let (_, mut far) = sessions();
    assert!(matches!(
        far.open(&Forger::new([0; 32]).message(2, b"")),
        Err(Error::Record)
    ));
    assert!(matches!(far.verify_end(), Err(Error::Record)));
}

#[test]
fn a_message_of_any_length_is_one_record() {
    let (mut near, mut far) = sessions();
    for length in [
        0usize, 1, 65517, 65518, 65519, 131_035, 131_036, 131_037, 300_000,
    ] {
        let message = vec![0x5a; length];
        let record = near.seal(&message).unwrap();
        assert_eq!(far.open(&record).unwrap().unwrap(), message, "{length}");
    }
}

#[test]
fn a_record_cut_at_any_noise_message_inside_it_is_refused() {
    let (mut near, mut far) = sessions();
    let record = near.seal(&vec![1; 100_000]).unwrap();
    assert!(matches!(far.open(&record[..2 + 65535]), Err(Error::Record)));
    let (mut near, mut far) = sessions();
    let record = near.seal(&vec![1; 100_000]).unwrap();
    assert!(matches!(far.open(&record[2 + 65535..]), Err(Error::Record)));
}

#[test]
fn a_limit_of_zero_passes_only_a_close_and_refuses_with_nothing_sent() {
    let (mut near, mut far) = limited(0, true);
    assert!(matches!(near.seal(b""), Err(Error::LimitReached)));
    assert!(matches!(near.seal(b"m"), Err(Error::LimitReached)));
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn with_rekey_off_the_limit_stops_a_direction_and_a_close_still_passes() {
    // Two 100-byte messages cost 149 each.
    let (mut near, mut far) = limited(298, false);
    let (first, second) = (near.seal(&[1; 100]).unwrap(), near.seal(&[2; 100]).unwrap());
    assert!(matches!(near.seal(&[3; 100]), Err(Error::LimitReached)));
    assert!(matches!(near.seal(&[3; 1]), Err(Error::LimitReached)));
    far.open(&first).unwrap().unwrap();
    far.open(&second).unwrap().unwrap();
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn with_rekey_on_the_key_changes_at_the_limit_and_the_stream_goes_on() {
    let (mut near, mut far) = limited(298, true);
    let mut lengths = Vec::new();
    for index in 0..7u8 {
        let message = vec![index; 100];
        let record = near.seal(&message).unwrap();
        lengths.push(record.len());
        assert_eq!(far.open(&record).unwrap().unwrap(), message);
    }
    // A record is 119 bytes, and every second one adds a 19-byte key change.
    assert_eq!(lengths, [119, 119, 138, 119, 138, 119, 138]);
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn a_key_change_inside_a_long_record_keeps_every_key_under_the_limit() {
    // Each whole part costs 65567, so at most one fits under this limit.
    let (mut near, mut far) = limited(70_000, true);
    let message = vec![9u8; 200_000];
    let record = near.seal(&message).unwrap();
    assert_eq!(far.open(&record).unwrap().unwrap(), message);
}

#[test]
fn a_long_record_refused_at_the_limit_leaves_the_session_as_it_was() {
    let (mut near, mut far) = limited(70_000, false);
    assert!(matches!(
        near.seal(&vec![9u8; 200_000]),
        Err(Error::LimitReached)
    ));
    let record = near.seal(b"after").unwrap();
    assert_eq!(far.open(&record).unwrap().unwrap(), b"after");
    // One part alone over the limit is refused with rekeying too.
    let (mut near, _) = limited(1000, true);
    assert!(matches!(
        near.seal(&vec![9u8; 2000]),
        Err(Error::LimitReached)
    ));
}

#[test]
fn each_side_decides_about_rekeying_for_itself() {
    // One end with a low limit for its own sending, and the other far above it.
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .key_limit(298)
        .build();
    let listening = Noise::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    let (near, far) = run(&dialing, &listening).unwrap();
    let (mut near, mut far) = (near.session, far.session);
    for index in 0..5u8 {
        let message = vec![index; 100];
        assert_eq!(
            far.open(&near.seal(&message).unwrap()).unwrap().unwrap(),
            message
        );
    }
}

#[test]
fn the_default_limit_is_two_to_the_38() {
    assert_eq!(DEFAULT_KEY_LIMIT, 1 << 38);
}

#[test]
fn split_halves_work_apart() {
    let (near, far) = sessions();
    let (mut sealer, _) = near.split();
    let (_, mut opener) = far.split();
    let record = sealer.seal(b"over there").unwrap();
    let writer = std::thread::spawn(move || {
        let close = sealer.close().unwrap();
        (sealer, close)
    });
    assert_eq!(opener.open(&record).unwrap().unwrap(), b"over there");
    let (_sealer, close) = writer.join().unwrap();
    assert_eq!(opener.open(&close).unwrap(), None);
    opener.verify_end().unwrap();
}

#[test]
fn a_lower_limit_is_for_a_sides_own_sending_only() {
    // One end with a limit of 200 against a peer at the default that does not change keys: the peer
    // is within the default, so what it sends opens, past 200 bytes on one key.
    for low_sends in [false, true] {
        let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let dialing = Noise::builder(client.clone())
            .responders(Trust::pinned([server.peer_id()]))
            .rekey(false)
            .build();
        let listening = Noise::builder(server)
            .initiators(Trust::pinned([client.peer_id()]))
            .key_limit(200)
            .build();
        let (near, far) = run(&dialing, &listening).unwrap();
        let (mut near, mut far) = (near.session, far.session);
        // `far` is the one limited to 200.
        let (sender, receiver) = if low_sends {
            (&mut far, &mut near)
        } else {
            (&mut near, &mut far)
        };
        for index in 0..5u8 {
            let message = vec![index; 100];
            let record = sender.seal(&message).unwrap();
            assert_eq!(receiver.open(&record).unwrap().unwrap(), message);
        }
    }
}
