//! The same parties as in `relay.rs` on real sockets, as a proxy between two TCP connections: a client
//! lured to it, pinning the real server, reaches that server through it. No TLS is involved, and none
//! could help: this relay would end it on both sides.

mod support;

use std::io::{self, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use coqui_peer::{
    Established, Method, drive_messages_until, drive_stream, read_frame, write_frame,
};
use coqui_peer_noise::{Error, FramedStream, MAX_HANDSHAKE_MESSAGE, MessageTransport, Session};
use support::pinned_pair;

/// One frame from `from` to `to`, unchanged.
fn forward(from: &mut TcpStream, to: &mut TcpStream) -> Vec<u8> {
    let frame = read_frame(from).unwrap();
    write_frame(to, &frame).unwrap();
    frame
}

/// A connected pair of listeners: where the client connects, and where the relay connects onward.
struct Sockets {
    inner: TcpListener,
    outer: TcpListener,
}

fn sockets() -> Sockets {
    Sockets {
        inner: TcpListener::bind("127.0.0.1:0").unwrap(),
        outer: TcpListener::bind("127.0.0.1:0").unwrap(),
    }
}

impl Sockets {
    /// The relay's two sockets, once the client has connected to it.
    fn relay_ends(self) -> (TcpStream, TcpStream, TcpListener) {
        let (near, _) = self.outer.accept().unwrap();
        let far = TcpStream::connect(self.inner.local_addr().unwrap()).unwrap();
        (near, far, self.inner)
    }
}

/// Runs both ends on threads, with the relay given as `relaying` on this one.
fn through<C, S, T, U>(
    client: C,
    server: S,
    relaying: impl FnOnce(&mut TcpStream, &mut TcpStream),
) -> (T, U)
where
    C: FnOnce(&mut TcpStream, Established<Session>) -> T + Send + 'static,
    S: FnOnce(&mut TcpStream, Established<Session>) -> U + Send + 'static,
    T: Send + 'static,
    U: Send + 'static,
{
    let (_, _, dialing, listening) = pinned_pair();
    let sockets = sockets();
    let outer = sockets.outer.local_addr().unwrap();
    let dial = thread::spawn(move || {
        let mut socket = TcpStream::connect(outer).unwrap();
        let established = drive_stream(dialing.initiate().unwrap(), &mut socket).unwrap();
        client(&mut socket, established)
    });
    let (mut near, mut far, inner) = sockets.relay_ends();
    let serve = thread::spawn(move || {
        let (mut socket, from) = inner.accept().unwrap();
        let established =
            drive_stream(listening.respond(Some(from)).unwrap(), &mut socket).unwrap();
        server(&mut socket, established)
    });
    // The three handshake messages pass unchanged, and both ends succeed.
    forward(&mut near, &mut far);
    forward(&mut far, &mut near);
    forward(&mut near, &mut far);
    relaying(&mut near, &mut far);
    (dial.join().unwrap(), serve.join().unwrap())
}

#[test]
fn a_relay_carries_the_proof_and_a_record_and_its_own_injected_message_is_refused() {
    let (replied, (opened, refused)) = through(
        |socket, mut established| {
            let record = established.session.seal(b"only for the server").unwrap();
            write_frame(socket, &record).unwrap();
            let reply = read_frame(socket).unwrap();
            established.session.open(&reply).unwrap().unwrap()
        },
        |socket, mut established| {
            let genuine = read_frame(socket).unwrap();
            let opened = established.session.open(&genuine).unwrap().unwrap();
            write_frame(socket, &established.session.seal(b"acknowledged").unwrap()).unwrap();
            // What the relay made up.
            let injected = read_frame(socket).unwrap();
            let refused = matches!(established.session.open(&injected), Err(Error::Record));
            (opened, refused)
        },
        |near, far| {
            let record = forward(near, far);
            assert!(!record.windows(4).any(|window| window == b"only"));
            forward(far, near);
            write_frame(far, br#"{"jsonrpc":"2.0","method":"session/prompt"}"#).unwrap();
        },
    );
    assert_eq!(replied, b"acknowledged");
    assert_eq!(opened, b"only for the server");
    assert!(refused, "the relay's message was believed");
}

#[test]
fn a_relay_swapping_two_records_is_refused() {
    let ((), refused) = through(
        |socket, mut established| {
            write_frame(socket, &established.session.seal(b"first").unwrap()).unwrap();
            write_frame(socket, &established.session.seal(b"second").unwrap()).unwrap();
        },
        |socket, mut established| {
            let record = read_frame(socket).unwrap();
            matches!(established.session.open(&record), Err(Error::Record))
        },
        |near, far| {
            let first = read_frame(near).unwrap();
            let second = read_frame(near).unwrap();
            write_frame(far, &second).unwrap();
            write_frame(far, &first).unwrap();
        },
    );
    assert!(refused);
}

#[test]
fn a_relay_reflecting_a_record_is_refused() {
    let (refused, ()) = through(
        |socket, mut established| {
            write_frame(socket, &established.session.seal(b"out").unwrap()).unwrap();
            let back = read_frame(socket).unwrap();
            matches!(established.session.open(&back), Err(Error::Record))
        },
        |_, _| {},
        |near, _far| {
            let record = read_frame(near).unwrap();
            write_frame(near, &record).unwrap();
        },
    );
    assert!(refused);
}

#[test]
fn a_relay_cutting_the_connection_is_seen_as_truncation_and_a_real_close_is_not() {
    fn ends(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
        read_frame(socket)
    }
    // Cut after one record, with the close record held back.
    let ((), (opened, verdict)) = through(
        |socket, mut established| {
            write_frame(socket, &established.session.seal(b"one").unwrap()).unwrap();
            write_frame(socket, &established.session.close().unwrap()).unwrap();
        },
        |socket, mut established| {
            let record = read_frame(socket).unwrap();
            let opened = established.session.open(&record).unwrap().unwrap();
            assert!(ends(socket).is_err(), "the connection is cut");
            (opened, established.session.verify_end())
        },
        |near, far| {
            forward(near, far);
            let _held_back = read_frame(near).unwrap();
            far.shutdown(Shutdown::Both).unwrap();
        },
    );
    assert_eq!(opened, b"one");
    assert!(matches!(verdict, Err(Error::Truncated)));

    // The same stream carried whole.
    let ((), verdict) = through(
        |socket, mut established| {
            write_frame(socket, &established.session.seal(b"one").unwrap()).unwrap();
            write_frame(socket, &established.session.close().unwrap()).unwrap();
        },
        |socket, mut established| {
            let record = read_frame(socket).unwrap();
            established.session.open(&record).unwrap().unwrap();
            let close = read_frame(socket).unwrap();
            assert_eq!(established.session.open(&close).unwrap(), None);
            established.session.verify_end()
        },
        |near, far| {
            forward(near, far);
            forward(near, far);
            far.shutdown(Shutdown::Write).unwrap();
        },
    );
    assert!(verdict.is_ok());
}

#[test]
fn a_relay_cannot_answer_for_a_pinned_server_on_real_sockets() {
    // The relay runs the responder's side itself, under its own key, on the socket the client dialled.
    let (client, _server, dialing, _) = pinned_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let relay_key = coqui_peer_noise::Identity::generate().unwrap();
    let as_relay = coqui_peer_noise::Noise::builder()
        .identity(relay_key)
        .initiators(coqui_peer_noise::Trust::pinned([client.peer_id()]))
        .build()
        .unwrap();
    let relaying = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        // It sees the failure as the connection going away.
        drive_stream(as_relay.respond(None).unwrap(), &mut socket)
            .map(|_| ())
            .is_err()
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let outcome = drive_stream(dialing.initiate().unwrap(), &mut socket);
    assert!(matches!(
        outcome,
        Err(coqui_peer::DriveError::Handshake(Error::Untrusted))
    ));
    drop(socket);
    assert!(relaying.join().unwrap(), "the relay learned no session");
}

#[test]
fn a_relay_holding_a_run_with_each_end_cannot_pass_one_ends_records_to_the_other() {
    // Misbinding: both ends trust the relay, each proved its key to the relay, and the relay wants
    // the server to take the client's record as coming from the relay. Each pair has its own keys.
    let (client, server, relay) = (
        coqui_peer_noise::Identity::generate().unwrap(),
        coqui_peer_noise::Identity::generate().unwrap(),
        coqui_peer_noise::Identity::generate().unwrap(),
    );
    let pinned = |id| coqui_peer_noise::Trust::pinned([id]);
    let dialing = coqui_peer_noise::Noise::builder()
        .identity(client.clone())
        .responders(pinned(relay.peer_id()))
        .build()
        .unwrap();
    let relay_answers = coqui_peer_noise::Noise::builder()
        .identity(relay.clone())
        .initiators(pinned(client.peer_id()))
        .build()
        .unwrap();
    let relay_dials = coqui_peer_noise::Noise::builder()
        .identity(relay.clone())
        .responders(pinned(server.peer_id()))
        .build()
        .unwrap();
    let listening = coqui_peer_noise::Noise::builder()
        .identity(server)
        .initiators(pinned(relay.peer_id()))
        .build()
        .unwrap();
    let sockets = sockets();
    let (outer, inner) = (
        sockets.outer.local_addr().unwrap(),
        sockets.inner.local_addr().unwrap(),
    );
    let serving = thread::spawn(move || {
        let (mut socket, _) = sockets.inner.accept().unwrap();
        let mut far = drive_stream(listening.respond(None).unwrap(), &mut socket).unwrap();
        let id = *far.session.id();
        let forwarded = read_frame(&mut socket).unwrap();
        (
            id,
            matches!(far.session.open(&forwarded), Err(Error::Record)),
        )
    });
    let dial = thread::spawn(move || {
        let mut socket = TcpStream::connect(outer).unwrap();
        let mut near = drive_stream(dialing.initiate().unwrap(), &mut socket).unwrap();
        write_frame(&mut socket, &near.session.seal(b"as the client").unwrap()).unwrap();
        *near.session.id()
    });
    let (mut from_client, _) = sockets.outer.accept().unwrap();
    let mut to_server = TcpStream::connect(inner).unwrap();
    drive_stream(relay_answers.respond(None).unwrap(), &mut from_client).unwrap();
    drive_stream(relay_dials.initiate().unwrap(), &mut to_server).unwrap();
    forward(&mut from_client, &mut to_server);
    let client_id = dial.join().unwrap();
    let (server_id, refused) = serving.join().unwrap();
    assert_ne!(client_id, server_id);
    assert!(refused, "the server believed a record of another run");
}

#[test]
fn a_relay_reflecting_a_handshake_message_is_refused_on_real_sockets() {
    let (_, _, dialing, _) = pinned_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let relaying = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let first = read_frame(&mut socket).unwrap();
        write_frame(&mut socket, &first).unwrap();
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let outcome = drive_stream(dialing.initiate().unwrap(), &mut socket);
    assert!(matches!(
        outcome,
        Err(coqui_peer::DriveError::Handshake(Error::Malformed))
    ));
    relaying.join().unwrap();
}

#[test]
fn a_binding_refuses_a_relay_that_ends_the_outer_channel_on_real_sockets() {
    let (_, _, dialing, listening) = pinned_pair();
    let sockets = sockets();
    let outer = sockets.outer.local_addr().unwrap();
    let dial = thread::spawn(move || {
        let mut socket = TcpStream::connect(outer).unwrap();
        let handshake = dialing.initiate().unwrap().bind(b"client's TLS").unwrap();
        drive_stream(handshake, &mut socket).map(|_| ())
    });
    let (mut near, mut far, inner) = sockets.relay_ends();
    let serve = thread::spawn(move || {
        let (mut socket, _) = inner.accept().unwrap();
        let handshake = listening
            .respond(None)
            .unwrap()
            .bind(b"server's TLS")
            .unwrap();
        drive_stream(handshake, &mut socket).map(|_| ())
    });
    forward(&mut near, &mut far);
    forward(&mut far, &mut near);
    // The initiator found out at the second message, and sends no third.
    assert!(read_frame(&mut near).is_err());
    drop((near, far));
    assert!(matches!(
        dial.join().unwrap(),
        Err(coqui_peer::DriveError::Handshake(Error::BadProof))
    ));
    assert!(serve.join().unwrap().is_err());
}

#[test]
fn a_long_message_crosses_a_real_socket_in_one_record() {
    let message = vec![0xa5u8; 300_000];
    let expected = message.clone();
    let ((), opened) = through(
        move |socket, mut established| {
            write_frame(socket, &established.session.seal(&message).unwrap()).unwrap();
        },
        |socket, mut established| {
            let record = read_frame(socket).unwrap();
            established.session.open(&record).unwrap().unwrap()
        },
        |near, far| {
            forward(near, far);
        },
    );
    assert_eq!(opened, expected);
}

#[test]
fn a_framed_stream_refuses_a_declared_length_before_reading_its_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut far = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (near, _) = listener.accept().unwrap();
    // One byte past the limit is declared, and no body follows: reading it would block.
    let declared = u32::try_from(MAX_HANDSHAKE_MESSAGE + 1).unwrap();
    far.write_all(&declared.to_be_bytes()).unwrap();
    let mut framed = FramedStream::new(near, MAX_HANDSHAKE_MESSAGE);
    let refused = framed.recv().unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);

    // Within the limit it passes, and the limit can be raised for records.
    let mut other = FramedStream::new(far, MAX_HANDSHAKE_MESSAGE);
    other.send(b"short").unwrap();
    framed.set_max_message(1 << 20);
    assert_eq!(framed.recv().unwrap(), b"short");
}

#[test]
fn a_handshake_runs_over_a_framed_stream_with_a_deadline() {
    let (_, _, dialing, listening) = pinned_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let serve = thread::spawn(move || {
        let (socket, from) = listener.accept().unwrap();
        let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
        let deadline = Instant::now() + Duration::from_secs(30);
        drive_messages_until(
            listening.respond(Some(from)).unwrap(),
            &mut framed,
            deadline,
        )
        .unwrap()
        .session
    });
    let mut framed = FramedStream::new(TcpStream::connect(address).unwrap(), MAX_HANDSHAKE_MESSAGE);
    let deadline = Instant::now() + Duration::from_secs(30);
    let near = drive_messages_until(dialing.initiate().unwrap(), &mut framed, deadline)
        .unwrap()
        .session;
    assert_eq!(near.id(), serve.join().unwrap().id());
}

#[test]
fn a_silent_peer_meets_the_callers_deadline() {
    let (_, _, dialing, _) = pinned_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut framed = FramedStream::new(
        TcpStream::connect(listener.local_addr().unwrap()).unwrap(),
        MAX_HANDSHAKE_MESSAGE,
    );
    let (_kept_open, _) = listener.accept().unwrap();
    let outcome = drive_messages_until(
        dialing.initiate().unwrap(),
        &mut framed,
        Instant::now() + Duration::from_millis(100),
    );
    assert!(matches!(outcome, Err(coqui_peer::DriveError::TimedOut)));
}
