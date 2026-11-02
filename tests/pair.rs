//! Pairing on a session: two strangers prove keys, the exchange runs sealed, and from then on the
//! full key is what the handshake proves. Nothing here involves TLS, so it holds behind a proxy.

mod support;

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use coqui_peer::pair::{
    CodeAlphabet, Mode, PairRefusal, Pairing, PairingDesk, PairingError, PairingJoiner,
    PairingOptions, PairingResponder, Pin, PinRole, Shown,
};
use coqui_peer::{
    Established, Handshake, InvitationOptions, Method, ReadTimeout, drive_messages, read_frame,
    write_frame,
};
use coqui_peer_noise::{
    Error, FramedStream, Identity, MAX_HANDSHAKE_MESSAGE, MAX_PAIRING_RECORD, MessageTransport,
    Noise, PairingMethod, PairingSession, Trust, TrustStore, random,
};
use support::{exchange, run};

struct Pipe {
    out: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<Vec<u8>>,
}

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
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

impl ReadTimeout for Pipe {
    fn set_read_timeout(&self, _: Option<core::time::Duration>) -> io::Result<()> {
        Ok(())
    }
}

fn pipes() -> (Pipe, Pipe) {
    let (to_a, a_inbox) = mpsc::channel();
    let (to_b, b_inbox) = mpsc::channel();
    (
        Pipe {
            out: to_b,
            inbox: a_inbox,
        },
        Pipe {
            out: to_a,
            inbox: b_inbox,
        },
    )
}

fn pairing_run(
    joining: &PairingMethod,
    responding: &PairingMethod,
) -> Result<(Established<PairingSession>, Established<PairingSession>), Error> {
    let (mut near, mut far) = (joining.initiate()?, responding.respond(None)?);
    while !(near.is_complete() && far.is_complete()) {
        while let Some(message) = near.transmit()? {
            far.receive(&message)?;
        }
        while let Some(message) = far.transmit()? {
            near.receive(&message)?;
        }
    }
    Ok((near.finish()?, far.finish()?))
}

fn strangers(joiner: &Identity, responder: &Identity) -> (PairingSession, PairingSession) {
    let (near, far) = pairing_run(
        &PairingMethod::new(joiner.clone()),
        &PairingMethod::new(responder.clone()),
    )
    .unwrap();
    (near.session, far.session)
}

struct World {
    store: TrustStore,
    desk: PairingDesk,
    _dir: tempfile::TempDir,
}

fn world_with(options: PairingOptions) -> World {
    let dir = tempfile::tempdir().unwrap();
    World {
        store: TrustStore::open(dir.path()).unwrap(),
        desk: PairingDesk::new(random()).with_options(options).unwrap(),
        _dir: dir,
    }
}

fn world() -> World {
    world_with(PairingOptions::default())
}

fn typed(pin: &str) -> Pairing {
    Pairing::pin(
        Pin::parse(&CodeAlphabet::pin(), pin).unwrap(),
        PinRole::Typed,
    )
}

fn other_pin(pin: &str) -> &'static str {
    if pin == "000000" { "000001" } else { "000000" }
}

/// One pairing attempt on its own connection: the joiner's and the responder's results.
fn attempt(
    world: &World,
    joiner: &Identity,
    responder: &Identity,
    pin: &str,
) -> (Result<(), Error>, Result<(), Error>) {
    let (near, far) = strangers(joiner, responder);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.respond(&store, &desk, None, &mut b).map(drop))
    };
    let joined = near
        .join(typed(pin), &mut a)
        .and_then(coqui_peer_noise::PairDial::finish)
        .map(drop);
    drop(a);
    (joined, serving.join().unwrap())
}

fn is_refusal(result: &Result<(), Error>, refusal: PairRefusal) -> bool {
    matches!(result, Err(Error::Pairing(PairingError::Refused(found))) if *found == refusal)
}

#[test]
fn a_pairing_session_holds_a_key_and_is_nobody() {
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (near, far) = strangers(&joiner, &responder);
    assert_eq!(near.peer_id(), responder.peer_id());
    assert_eq!(far.peer_id(), joiner.peer_id());
    assert_eq!(near.peer().method, "noise");
    assert_eq!(near.peer(), &responder.key_material());
    assert_eq!(near.id(), far.id());
    let (at_joiner, at_responder) = (near.pair_channel().unwrap(), far.pair_channel().unwrap());
    assert!(!at_joiner.verified && !at_responder.verified);
    assert_eq!(at_joiner.binding, at_responder.binding);
    assert_eq!(at_joiner.local, joiner.key_material());
    assert_eq!(at_joiner.remote, Some(responder.key_material()));
    let method = PairingMethod::new(joiner);
    for setting in ["initiators", "responders"] {
        assert!(method.weakened().iter().any(|w| w.setting == setting));
    }
    // `PairingSession` has no `seal` or `open`, and `Trust` has no way to admit a stranger: the
    // doctests on both are `compile_fail`.
}

#[test]
fn a_typed_pin_pairs_two_strangers_and_the_full_key_is_proved_afterwards() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (near, far) = strangers(&joiner, &responder);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.respond(&store, &desk, None, &mut b))
    };
    let paired = near
        .join(typed(shown.pin.as_str()), &mut a)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(paired.peer, responder.key_material());
    assert_eq!(paired.mode, Mode::Pin);
    assert_eq!(serving.join().unwrap().unwrap().peer.id(), joiner.peer_id());
    assert!(world.store.is_accepted(&joiner.peer_id()));
    assert_eq!(
        world.store.accepted_key(&joiner.peer_id()),
        Some(joiner.key_material())
    );

    // The next connection is the ordinary method, with no PIN and each key pinned.
    let dialing = Noise::new(joiner.clone()).with_responders(Trust::pinned([paired.peer.id()]));
    let listening = Noise::new(responder).with_initiators(Trust::Store(world.store.clone()));
    let (at_joiner, at_responder) = run(&dialing, &listening).unwrap();
    assert_eq!(at_responder.peer, joiner.peer_id());
    assert_eq!(at_joiner.peer, paired.peer.id());
}

#[test]
fn before_pairing_the_ordinary_method_refuses_the_stranger() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = Noise::new(joiner.clone()).with_responders(Trust::pinned([responder.peer_id()]));
    let listening = Noise::new(responder).with_initiators(Trust::Store(world.store.clone()));
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_wrong_pin_is_refused_at_the_confirmation_and_nobody_is_accepted() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (joined, served) = attempt(&world, &joiner, &responder, other_pin(shown.pin.as_str()));
    assert!(is_refusal(&joined, PairRefusal::WrongCode));
    // The joiner found out first, and says so, so the responder learns why rather than a cut.
    assert!(is_refusal(&served, PairRefusal::WrongCode), "{served:?}");
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_wrong_pin_uses_up_a_pin_of_one_attempt_and_a_new_pin_pairs() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (joined, _) = attempt(&world, &joiner, &responder, other_pin(shown.pin.as_str()));
    assert!(is_refusal(&joined, PairRefusal::WrongCode));
    assert!(world.desk.shown_pin().is_none(), "the PIN is used up");

    // The right PIN after it is too late: that is what stops a second guess.
    let (joined, served) = attempt(&world, &joiner, &responder, shown.pin.as_str());
    assert!(is_refusal(&joined, PairRefusal::Exhausted));
    assert!(is_refusal(&served, PairRefusal::Exhausted));
    assert!(!world.store.is_accepted(&joiner.peer_id()));

    // A person starts again, on a new connection with a new session.
    let shown = world.desk.show_pin().unwrap();
    let (joined, served) = attempt(&world, &joiner, &responder, shown.pin.as_str());
    joined.unwrap();
    served.unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_pin_of_several_attempts_takes_that_many_and_no_more() {
    let world = world_with(PairingOptions {
        pin_attempts: 3,
        ..PairingOptions::default()
    });
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let wrong = other_pin(shown.pin.as_str());
    for _ in 0..2 {
        let (joined, _) = attempt(&world, &joiner, &responder, wrong);
        assert!(is_refusal(&joined, PairRefusal::WrongCode));
    }
    assert!(world.desk.shown_pin().is_some());
    let (joined, served) = attempt(&world, &joiner, &responder, shown.pin.as_str());
    joined.unwrap();
    served.unwrap();
    assert!(world.desk.shown_pin().is_none(), "every attempt counted");
}

#[test]
fn a_responder_with_no_pin_shown_refuses_at_the_first_message() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (joined, served) = attempt(&world, &joiner, &responder, "123456");
    assert!(is_refusal(&joined, PairRefusal::Exhausted));
    assert!(is_refusal(&served, PairRefusal::Exhausted));
}

#[test]
fn an_invitation_goes_only_to_the_key_the_handshake_proved_to_be_the_inviters() {
    let world = world();
    let (joiner, inviter, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let invitation = world
        .store
        .invite(&random(), InvitationOptions::default(), "tablet")
        .unwrap();

    // A session whose real peer is someone else: the secret is never sent.
    let (to_relay, at_relay) = strangers(&joiner, &relay);
    let (mut a, b) = pipes();
    let refused = to_relay.join(
        Pairing::invitation(inviter.peer_id(), invitation.secret),
        &mut a,
    );
    assert!(matches!(
        refused,
        Err(Error::Pairing(PairingError::Unverified))
    ));
    assert!(b.inbox.try_recv().is_err(), "nothing went out");
    drop(at_relay);

    // A pin on the inviter stops such a relay at the handshake, before pairing is reached.
    let pinned =
        PairingMethod::new(joiner.clone()).with_responders(Trust::pinned([inviter.peer_id()]));
    assert!(matches!(
        pairing_run(&pinned, &PairingMethod::new(relay)),
        Err(Error::Untrusted)
    ));

    // With the real inviter it pairs.
    let (near, far) = pairing_run(&pinned, &PairingMethod::new(inviter.clone())).unwrap();
    assert!(near.session.pair_channel().unwrap().verified);
    assert!(!far.session.pair_channel().unwrap().verified);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.session.respond(&store, &desk, None, &mut b))
    };
    let paired = near
        .session
        .join(
            Pairing::invitation(inviter.peer_id(), invitation.secret),
            &mut a,
        )
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(paired.peer.id(), inviter.peer_id());
    serving.join().unwrap().unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn the_device_flow_needs_a_verified_responder_and_runs_through_the_driver() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());

    // Accepting any proved key does not verify the responder.
    let (near, _far) = strangers(&joiner, &responder);
    let (mut a, _b) = pipes();
    assert!(matches!(
        near.join(Pairing::device("kitchen"), &mut a),
        Err(Error::Pairing(PairingError::Unverified))
    ));

    let pinned =
        PairingMethod::new(joiner.clone()).with_responders(Trust::pinned([responder.peer_id()]));
    let (near, far) = pairing_run(&pinned, &PairingMethod::new(responder.clone())).unwrap();
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.session.respond(&store, &desk, None, &mut b))
    };
    let dial = near
        .session
        .join(Pairing::device("kitchen"), &mut a)
        .unwrap();
    let Some(Shown::UserCode { code, .. }) = dial.shown() else {
        panic!("a user code to show");
    };
    let found = world.desk.find_device("operator", code.as_str()).unwrap();
    assert_eq!(found.peer, joiner.peer_id());
    world.desk.approve(&found).unwrap();
    assert_eq!(dial.finish().unwrap().mode, Mode::Device);
    serving.join().unwrap().unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

/// Runs a joiner and a responder that talk directly, as a relay would pass them, to their end.
fn converse(
    joiner: &mut PairingJoiner,
    responder: &mut PairingResponder,
) -> Result<(), PairingError> {
    loop {
        let mut moved = false;
        while let Some(message) = joiner.transmit() {
            responder.receive(&message)?;
            moved = true;
        }
        while let Some(message) = responder.transmit() {
            joiner.receive(&message)?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
}

#[test]
fn a_relay_forwarding_unchanged_between_its_own_sessions_fails_at_the_first_message() {
    let world = world();
    let (joiner, responder, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let shown = world.desk.show_pin().unwrap();
    let (joining, _) = strangers(&joiner, &relay);
    let (_, responding) = strangers(&relay, &responder);
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    // The hello names the joiner, and the responder's session proved the relay.
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Protocol)
    ));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_relay_with_a_key_of_its_own_on_each_side_fails_the_pin_confirmation() {
    let world = world();
    let relay_world = self::world();
    let (joiner, responder, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    // The person types the responder's PIN at the joiner. The relay does not know it.
    let shown = world.desk.show_pin().unwrap();

    // Toward the joiner the relay is a responder, with a PIN of its own; it must guess.
    let (joining, relay_toward_joiner) = strangers(&joiner, &relay);
    let relay_pin = relay_world.desk.show_pin().unwrap();
    assert_ne!(
        relay_pin.pin.as_str(),
        shown.pin.as_str(),
        "a one in 10^6 chance"
    );
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        relay_toward_joiner.pair_channel().unwrap(),
        &relay_world.store,
        &relay_world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!relay_world.store.is_accepted(&joiner.peer_id()));

    // Toward the responder the relay is a joiner, and its guess burns the PIN.
    let (relay_toward_responder, responding) = strangers(&relay, &responder);
    let mut near = typed(other_pin(shown.pin.as_str()))
        .join(relay_toward_responder.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!world.store.is_accepted(&relay.peer_id()));
    assert!(world.desk.shown_pin().is_none(), "the PIN is used up");
}

#[test]
fn two_sessions_of_the_same_peers_do_not_share_a_pairing() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    // The right keys and the right PIN, on two runs: only the binding differs.
    let (joining, _) = strangers(&joiner, &responder);
    let (_, responding) = strangers(&joiner, &responder);
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

/// An ordinary session opposite a pairing session: the same handshake on the wire, and a peer that can
/// say whatever it likes in the exchange.
fn opposite_a_responder(
    joiner: &Identity,
    responder: &Identity,
) -> (coqui_peer_noise::Session, PairingSession) {
    let dialing = Noise::new(joiner.clone()).with_responders(Trust::pinned([responder.peer_id()]));
    let (mut near, mut far) = (
        dialing.initiate().unwrap(),
        PairingMethod::new(responder.clone()).respond(None).unwrap(),
    );
    while !(near.is_complete() && far.is_complete()) {
        while let Some(message) = near.transmit().unwrap() {
            far.receive(&message).unwrap();
        }
        while let Some(message) = far.transmit().unwrap() {
            near.receive(&message).unwrap();
        }
    }
    (
        near.finish().unwrap().session,
        far.finish().unwrap().session,
    )
}

#[test]
fn a_responder_reports_a_close_in_the_middle_as_truncated() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    world.desk.show_pin().unwrap();
    let (mut peer, pairing) = opposite_a_responder(&joiner, &responder);
    let (mut a, mut b) = pipes();
    a.send(&peer.close().unwrap()).unwrap();
    assert!(matches!(
        pairing.respond(&world.store, &world.desk, None, &mut b),
        Err(Error::Truncated)
    ));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_joiner_reports_a_close_in_the_middle_as_truncated() {
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let listening =
        Noise::new(responder.clone()).with_initiators(Trust::pinned([joiner.peer_id()]));
    let (mut near, mut far) = (
        PairingMethod::new(joiner).initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    while !(near.is_complete() && far.is_complete()) {
        while let Some(message) = near.transmit().unwrap() {
            far.receive(&message).unwrap();
        }
        while let Some(message) = far.transmit().unwrap() {
            near.receive(&message).unwrap();
        }
    }
    let (pairing, mut peer) = (
        near.finish().unwrap().session,
        far.finish().unwrap().session,
    );
    let (mut a, mut b) = pipes();
    b.send(&peer.close().unwrap()).unwrap();
    assert!(matches!(
        pairing.join(typed("123456"), &mut a),
        Err(Error::Truncated)
    ));
}

#[test]
fn the_methods_refuse_each_others_gaps() {
    let identity = Identity::generate().unwrap();
    let other = Identity::generate().unwrap();
    // `Noise` with an empty pin set admits no stranger, whatever `PairingMethod` would do.
    let dialing = Noise::new(other.clone()).with_responders(Trust::pinned([identity.peer_id()]));
    let listening = Noise::new(identity).with_initiators(Trust::pinned([]));
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
}

type Tamper = Box<dyn Fn(usize, Vec<u8>) -> Option<Vec<u8>> + Send>;

/// A plain relay on real sockets: each direction's frames through `tamper`, whose `None` ends the
/// connection in that direction.
fn relayed(
    near: TcpStream,
    far: TcpStream,
    tamper: impl Fn(usize, Vec<u8>) -> Option<Vec<u8>> + Send + Clone + 'static,
) -> [thread::JoinHandle<()>; 2] {
    let pass = |mut from: TcpStream, mut to: TcpStream, tamper: Tamper| {
        thread::spawn(move || {
            let mut index = 0;
            while let Ok(frame) = read_frame(&mut from) {
                let Some(frame) = tamper(index, frame) else {
                    break;
                };
                if write_frame(&mut to, &frame).is_err() {
                    break;
                }
                index += 1;
            }
            let _ = to.shutdown(std::net::Shutdown::Both);
            let _ = from.shutdown(std::net::Shutdown::Both);
        })
    };
    [
        pass(
            near.try_clone().unwrap(),
            far.try_clone().unwrap(),
            Box::new(tamper.clone()),
        ),
        pass(far, near, Box::new(|_, frame| Some(frame))),
    ]
}

fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (far, _) = listener.accept().unwrap();
    (near, far)
}

/// A pairing on real sockets through a relay. `tamper` sees each frame the joiner sends: the three
/// handshake frames count, so a pairing record is index 2 onward after the two the joiner sends.
fn over_sockets(
    world: &World,
    joiner: &Identity,
    responder: &Identity,
    pin: String,
    tamper: impl Fn(usize, Vec<u8>) -> Option<Vec<u8>> + Send + Clone + 'static,
) -> (Result<(), Error>, Result<(), Error>) {
    let (joiner_end, relay_near) = connected();
    let (relay_far, responder_end) = connected();
    let relay = relayed(relay_near, relay_far, tamper);
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        let method = PairingMethod::new(responder.clone());
        thread::spawn(move || {
            let mut framed = FramedStream::new(responder_end, MAX_HANDSHAKE_MESSAGE);
            let established = drive_messages(method.respond(None).unwrap(), &mut framed)
                .map_err(|_| Error::BadProof)?;
            framed.set_max_message(MAX_PAIRING_RECORD);
            established
                .session
                .respond(&store, &desk, None, &mut framed)
                .map(drop)
        })
    };
    let mut framed = FramedStream::new(joiner_end, MAX_HANDSHAKE_MESSAGE);
    let method = PairingMethod::new(joiner.clone());
    let joined = drive_messages(method.initiate().unwrap(), &mut framed)
        .map_err(|_| Error::BadProof)
        .and_then(|established| {
            framed.set_max_message(MAX_PAIRING_RECORD);
            established
                .session
                .join(typed(&pin), &mut framed)
                .and_then(coqui_peer_noise::PairDial::finish)
                .map(drop)
        });
    drop(framed);
    let served = serving.join().unwrap();
    for pass in relay {
        pass.join().unwrap();
    }
    (joined, served)
}

#[test]
fn a_relay_on_real_sockets_that_forwards_pairs_the_real_parties() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (joined, served) = over_sockets(
        &world,
        &joiner,
        &responder,
        shown.pin.as_str().to_owned(),
        |_, frame| Some(frame),
    );
    joined.unwrap();
    served.unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_relay_altering_any_sealed_pairing_record_is_refused_and_nobody_is_accepted() {
    // The joiner sends two handshake messages, then its hello, its PAKE message and its confirmation.
    for target in 2..5 {
        let world = world();
        let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let shown = world.desk.show_pin().unwrap();
        let (joined, served) = over_sockets(
            &world,
            &joiner,
            &responder,
            shown.pin.as_str().to_owned(),
            move |index, mut frame| {
                if index == target {
                    let last = frame.len() - 1;
                    frame[last] ^= 1;
                }
                Some(frame)
            },
        );
        assert!(
            matches!(served, Err(Error::Record)),
            "frame {target}: {served:?}"
        );
        assert!(joined.is_err(), "frame {target}");
        assert!(
            !world.store.is_accepted(&joiner.peer_id()),
            "frame {target}"
        );
    }
}

#[test]
fn a_relay_cutting_the_exchange_before_the_confirmation_leaves_nobody_accepted() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (joined, served) = over_sockets(
        &world,
        &joiner,
        &responder,
        shown.pin.as_str().to_owned(),
        |index, frame| (index != 4).then_some(frame),
    );
    assert!(joined.is_err());
    assert!(served.is_err());
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_framed_stream_at_the_stated_limit_carries_the_longest_exchange() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let pinned =
        PairingMethod::new(joiner.clone()).with_responders(Trust::pinned([responder.peer_id()]));
    let (near, far) = pairing_run(&pinned, &PairingMethod::new(responder)).unwrap();
    let (a, b) = connected();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || {
            let mut framed = FramedStream::new(b, MAX_PAIRING_RECORD);
            far.session.respond(&store, &desk, None, &mut framed)
        })
    };
    let mut framed = FramedStream::new(a, MAX_PAIRING_RECORD);
    let label = "k".repeat(255);
    let dial = near
        .session
        .join(Pairing::device(&label), &mut framed)
        .unwrap();
    let Some(Shown::UserCode { code, .. }) = dial.shown() else {
        panic!("a user code to show");
    };
    let found = world.desk.find_device("operator", code.as_str()).unwrap();
    assert_eq!(found.label, label);
    world.desk.approve(&found).unwrap();
    dial.finish().unwrap();
    serving.join().unwrap().unwrap();
}

/// Only a joiner's hello, sealed: the record a joiner sends before it hears anything.
fn sealed_hello(session: PairingSession) -> Vec<u8> {
    struct Keep(Vec<Vec<u8>>);
    impl MessageTransport for Keep {
        fn send(&mut self, message: &[u8]) -> io::Result<()> {
            self.0.push(message.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> io::Result<Vec<u8>> {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
    let mut kept = Keep(Vec::new());
    assert!(session.join(typed("123456"), &mut kept).is_err());
    kept.0.remove(0)
}

#[test]
fn a_joiner_that_stops_answering_is_told_the_exchange_expired() {
    let world = world_with(PairingOptions {
        pin_ttl: core::time::Duration::from_millis(200),
        ..PairingOptions::default()
    });
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    world.desk.show_pin().unwrap();
    let (near, far) = strangers(&joiner, &responder);
    let (a, b) = connected();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || {
            let mut framed = FramedStream::new(b, MAX_PAIRING_RECORD);
            far.respond(&store, &desk, None, &mut framed).map(drop)
        })
    };
    let mut framed = FramedStream::new(a, MAX_PAIRING_RECORD);
    framed.send(&sealed_hello(near)).unwrap();
    let served = serving.join().unwrap();
    assert!(is_refusal(&served, PairRefusal::Expired), "{served:?}");
    // What the responder said to the hello, then its refusal: each a whole record.
    assert!(framed.recv().is_ok());
    assert!(framed.recv().is_ok(), "the refusal reached the joiner");
}
