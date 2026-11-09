//! A PIN pairing, then the ordinary method, over TCP, for the JavaScript interoperability tests and the
//! proxy run. Frames are coqui-peer's: four big-endian length bytes, then the message. Lines on stdin and
//! stdout say who is who, and stderr says what was proved.
//!
//! `pair responder <store-directory>`: prints `{"peerId":...}`, listens on a loopback port and prints it,
//! then shows a PIN as `{"pin":...}`. Each connection tries to pair: a refusal prints `{"refused":...}`,
//! and a PIN that was used up is replaced, printing the next one. Once paired, it prints
//! `{"paired":...}` and answers one more connection with `Noise` over the store, echoing each record and
//! answering a close with its own.
//!
//! `pair joiner`: prints `{"peerId":...}`, reads the port and then one PIN per attempt. A refusal prints
//! `{"refused":...}`, and an empty line gives up. Once paired, it prints `{"paired":...}`, dials again
//! with `Noise` pinned on that key, sends one sealed record, prints the echo, closes.
//!
//! A refused handshake or record exits with status 3; a stream that ends with no close record, with 4.

use std::error::Error as StdError;
use std::io::{self, BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::ExitCode;

use coqui_peer::pair::{CodeAlphabet, Pairing, PairingDesk, Pin, PinRole};
use coqui_peer::{Method, drive_messages, read_frame, write_frame};
use coqui_peer_noise::{
    Error, FramedStream, Identity, MAX_HANDSHAKE_MESSAGE, MAX_PAIRING_RECORD, Noise, PairingMethod,
    PeerId, Session, Trust, TrustStore, random,
};

type Failure = Box<dyn StdError>;

const REFUSED: u8 = 3;
const TRUNCATED: u8 = 4;

fn say(text: &str) -> Result<(), Failure> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}

fn reason(error: &Error) -> String {
    match error {
        Error::Pairing(inner) => format!("{inner:?}"),
        other => format!("{other:?}"),
    }
}

/// One echo stream under the ordinary method, as `examples/peer.rs` runs it.
fn echo(mut session: Session, socket: &mut TcpStream) -> Result<u8, Failure> {
    loop {
        let sealed = match read_frame(socket) {
            Ok(sealed) => sealed,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(if matches!(session.verify_end(), Err(Error::Truncated)) {
                    TRUNCATED
                } else {
                    0
                });
            }
            Err(error) => return Err(error.into()),
        };
        match session.open(&sealed) {
            Ok(Some(message)) => {
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&message);
                write_frame(socket, &session.seal(&reply)?)?;
            }
            Ok(None) => {
                write_frame(socket, &session.close()?)?;
                session.verify_end()?;
                return Ok(0);
            }
            Err(error) => {
                eprintln!("refused a record: {error:?}");
                return Ok(REFUSED);
            }
        }
    }
}

fn pair_one(
    method: &PairingMethod,
    store: &TrustStore,
    desk: &PairingDesk,
    socket: TcpStream,
) -> Result<PeerId, Error> {
    let source = socket.peer_addr().ok();
    let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
    let established = drive_messages(method.respond(source)?, &mut framed).map_err(drive_error)?;
    framed.set_max_message(MAX_PAIRING_RECORD);
    let paired = established
        .session
        .respond(store, desk, source, &mut framed)?;
    Ok(paired.peer.id())
}

fn drive_error(error: coqui_peer::DriveError<Error>) -> Error {
    match error {
        coqui_peer::DriveError::Handshake(error) => error,
        _ => Error::Malformed,
    }
}

fn respond(identity: Identity, directory: &Path) -> Result<u8, Failure> {
    let store = TrustStore::open(directory)?;
    let desk = PairingDesk::new(random());
    let method = PairingMethod::builder(identity.clone()).build();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    say(&listener.local_addr()?.port().to_string())?;
    say(&format!(
        "{{\"pin\":\"{}\"}}",
        desk.show_pin()?.pin.as_str()
    ))?;
    let joiner = loop {
        let (socket, _) = listener.accept()?;
        match pair_one(&method, &store, &desk, socket) {
            Ok(joiner) => break joiner,
            Err(error) => {
                eprintln!("refused: {error:?}");
                say(&format!("{{\"refused\":\"{}\"}}", reason(&error)))?;
                if desk.shown_pin().is_none() {
                    say(&format!(
                        "{{\"pin\":\"{}\"}}",
                        desk.show_pin()?.pin.as_str()
                    ))?;
                }
            }
        }
    };
    say(&format!("{{\"paired\":\"{joiner}\"}}"))?;
    let (socket, source) = listener.accept()?;
    let ordinary = Noise::builder(identity)
        .initiators(Trust::Store(store))
        .build();
    let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
    let established = match drive_messages(ordinary.respond(Some(source))?, &mut framed) {
        Ok(established) => established,
        Err(error) => {
            eprintln!("refused: {error:?}");
            return Ok(REFUSED);
        }
    };
    eprintln!("verified {}", established.peer);
    say(&format!(
        "{{\"id\":\"{}\"}}",
        data_encoding::HEXLOWER.encode(established.session.id())
    ))?;
    echo(established.session, &mut framed.into_inner())
}

fn join_one(method: &PairingMethod, port: u16, pin: &str) -> Result<PeerId, Error> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
    let established = drive_messages(method.initiate()?, &mut framed).map_err(drive_error)?;
    framed.set_max_message(MAX_PAIRING_RECORD);
    let pin = Pin::parse(&CodeAlphabet::pin(), pin).map_err(|_| Error::Malformed)?;
    let paired = established
        .session
        .join(Pairing::pin(pin, PinRole::Typed), &mut framed)?
        .finish()?;
    Ok(paired.peer.id())
}

fn join(
    identity: Identity,
    lines: &mut impl Iterator<Item = io::Result<String>>,
) -> Result<u8, Failure> {
    let port: u16 = lines.next().ok_or("the input ended")??.parse()?;
    let method = PairingMethod::builder(identity.clone()).build();
    let responder = loop {
        let pin = lines.next().ok_or("the input ended")??;
        if pin.is_empty() {
            return Ok(REFUSED);
        }
        match join_one(&method, port, &pin) {
            Ok(responder) => break responder,
            Err(error) => {
                eprintln!("refused: {error:?}");
                say(&format!("{{\"refused\":\"{}\"}}", reason(&error)))?;
            }
        }
    };
    say(&format!("{{\"paired\":\"{responder}\"}}"))?;
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    let ordinary = Noise::builder(identity)
        .responders(Trust::pinned([responder]))
        .build();
    let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
    let established = match drive_messages(ordinary.initiate()?, &mut framed) {
        Ok(established) => established,
        Err(error) => {
            eprintln!("refused: {error:?}");
            return Ok(REFUSED);
        }
    };
    say(&format!(
        "{{\"id\":\"{}\"}}",
        data_encoding::HEXLOWER.encode(established.session.id())
    ))?;
    let mut session = established.session;
    let mut socket = framed.into_inner();
    write_frame(&mut socket, &session.seal(b"ping from rust")?)?;
    let echo = session
        .open(&read_frame(&mut socket)?)?
        .ok_or("a close, not the echo")?;
    say(core::str::from_utf8(&echo)?)?;
    write_frame(&mut socket, &session.close()?)?;
    if session.open(&read_frame(&mut socket)?)?.is_some() {
        return Err("a message where the close was expected".into());
    }
    session.verify_end()?;
    Ok(0)
}

fn main() -> Result<ExitCode, Failure> {
    let mut arguments = std::env::args().skip(1);
    let role = arguments.next().ok_or("a role is required")?;
    let identity = Identity::generate()?;
    say(&format!("{{\"peerId\":\"{}\"}}", identity.peer_id()))?;
    let status = match role.as_str() {
        "responder" => {
            let directory = arguments.next().ok_or("a store directory is required")?;
            respond(identity, Path::new(&directory))?
        }
        "joiner" => join(identity, &mut io::stdin().lock().lines())?,
        _ => return Err("the role is responder or joiner".into()),
    };
    Ok(ExitCode::from(status))
}
