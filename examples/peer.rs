//! One end of the handshake and an echo over TCP, for the JavaScript interoperability tests. Frames are
//! coqui-peer's: four big-endian length bytes, then the message. Lines on stdin and stdout say who is
//! who, and stderr says what was proved.
//!
//! `peer responder`: prints `{"peerId":...}`, reads the client's id as a line, listens on a loopback
//! port and prints it, answers one connection, echoes each record, and answers a close with its own.
//! `peer initiator`: prints `{"peerId":...}`, reads the responder's id and a port as two lines, dials,
//! sends one sealed record, prints the echo, closes.
//!
//! A refused handshake exits with status 3; a stream that ends with no close record, with status 4.

use std::error::Error as StdError;
use std::io::{self, BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use coqui_peer::{DriveError, Established, Method, drive_messages, read_frame, write_frame};
use coqui_peer_noise::{
    Error, FramedStream, Identity, MAX_HANDSHAKE_MESSAGE, Noise, PeerId, Session, Trust,
};

type Failure = Box<dyn StdError>;

const REFUSED: u8 = 3;
const TRUNCATED: u8 = 4;

fn next(lines: &mut impl Iterator<Item = io::Result<String>>) -> Result<String, Failure> {
    Ok(lines.next().ok_or("the input ended")??)
}

fn say(text: &str) -> Result<(), Failure> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}

fn prove(
    handshake: coqui_peer_noise::NoiseHandshake,
    socket: TcpStream,
) -> Result<Result<(Established<Session>, TcpStream), u8>, Failure> {
    let mut framed = FramedStream::new(socket, MAX_HANDSHAKE_MESSAGE);
    match drive_messages(handshake, &mut framed) {
        Ok(established) => {
            eprintln!("verified {}", established.peer);
            say(&format!(
                "{{\"id\":\"{}\"}}",
                data_encoding::HEXLOWER.encode(established.session.id())
            ))?;
            Ok(Ok((established, framed.into_inner())))
        }
        Err(DriveError::Handshake(error)) => {
            eprintln!("refused: {error:?}");
            Ok(Err(REFUSED))
        }
        Err(error) => Err(error.into()),
    }
}

/// The next record, or `None` when the connection ended.
fn record(socket: &mut TcpStream) -> Result<Option<Vec<u8>>, Failure> {
    match read_frame(socket) {
        Ok(record) => Ok(Some(record)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn respond(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    identity: Identity,
) -> Result<u8, Failure> {
    let allowed: PeerId = next(lines)?.parse()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    say(&listener.local_addr()?.port().to_string())?;
    let (socket, source) = listener.accept()?;
    let method = Noise::builder(identity)
        .initiators(Trust::pinned([allowed]))
        .build();
    let (established, mut socket) = match prove(method.respond(Some(source))?, socket)? {
        Ok(proved) => proved,
        Err(status) => return Ok(status),
    };
    let mut session = established.session;
    loop {
        let Some(sealed) = record(&mut socket)? else {
            return Ok(if matches!(session.verify_end(), Err(Error::Truncated)) {
                TRUNCATED
            } else {
                0
            });
        };
        match session.open(&sealed) {
            Ok(Some(message)) => {
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&message);
                write_frame(&mut socket, &session.seal(&reply)?)?;
            }
            Ok(None) => {
                write_frame(&mut socket, &session.close()?)?;
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

fn initiate(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    identity: Identity,
) -> Result<u8, Failure> {
    let expected: PeerId = next(lines)?.parse()?;
    let port: u16 = next(lines)?.parse()?;
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    let method = Noise::builder(identity)
        .responders(Trust::pinned([expected]))
        .build();
    let (established, mut socket) = match prove(method.initiate()?, socket)? {
        Ok(proved) => proved,
        Err(status) => return Ok(status),
    };
    let mut session = established.session;
    write_frame(&mut socket, &session.seal(b"ping from rust")?)?;
    let Some(reply) = record(&mut socket)? else {
        return Ok(TRUNCATED);
    };
    let Some(echo) = session.open(&reply)? else {
        return Err("a close where the echo was expected".into());
    };
    say(core::str::from_utf8(&echo)?)?;
    write_frame(&mut socket, &session.close()?)?;
    let Some(close) = record(&mut socket)? else {
        return Ok(TRUNCATED);
    };
    if session.open(&close)?.is_some() {
        return Err("a message where the close was expected".into());
    }
    session.verify_end()?;
    Ok(0)
}

fn main() -> Result<ExitCode, Failure> {
    let role = std::env::args().nth(1).ok_or("a role is required")?;
    let identity = Identity::generate()?;
    say(&format!("{{\"peerId\":\"{}\"}}", identity.peer_id()))?;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let status = match role.as_str() {
        "responder" => respond(&mut lines, identity)?,
        "initiator" => initiate(&mut lines, identity)?,
        _ => return Err("the role is responder or initiator".into()),
    };
    Ok(ExitCode::from(status))
}
