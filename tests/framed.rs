//! `FramedStream` on real sockets: its read timeout bounds a whole frame, however the bytes arrive,
//! and its limit is the same in both directions.

use core::time::Duration;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

use coqui_peer::{DriveError, Method, ReadTimeout, drive_messages_until};
use coqui_peer_noise::{
    CurrentReadTimeout, FramedStream, Identity, MAX_HANDSHAKE_MESSAGE, MessageTransport, Noise,
    Trust,
};

fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (far, _) = listener.accept().unwrap();
    (near, far)
}

/// Writes `bytes` one at a time, `gap` apart, until the peer goes away.
fn drip(mut socket: TcpStream, bytes: Vec<u8>, gap: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for byte in bytes {
            if socket.write_all(&[byte]).is_err() {
                return;
            }
            thread::sleep(gap);
        }
    })
}

fn frame_of(length: u32) -> Vec<u8> {
    let mut frame = length.to_be_bytes().to_vec();
    frame.resize(4 + length as usize, 0x5a);
    frame
}

#[test]
fn a_read_timeout_bounds_a_whole_frame_however_slowly_it_arrives() {
    let (near, far) = connected();
    let sender = drip(far, frame_of(40), Duration::from_millis(100));
    let mut framed = FramedStream::new(near, 64);
    framed
        .set_read_timeout(Some(Duration::from_millis(350)))
        .unwrap();
    let started = Instant::now();
    let error = framed
        .recv()
        .expect_err("one byte at a time must not outlast it");
    let taken = started.elapsed();
    assert!(
        matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
        "{error:?}"
    );
    assert!(taken < Duration::from_secs(2), "ended after {taken:?}");
    drop(framed);
    sender.join().unwrap();
}

#[test]
fn a_frame_within_its_timeout_arrives_whole() {
    let (near, far) = connected();
    let sender = drip(far, frame_of(5), Duration::from_millis(10));
    let mut framed = FramedStream::new(near, 64);
    framed
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    assert_eq!(framed.recv().unwrap(), [0x5a; 5]);
    sender.join().unwrap();
}

#[test]
fn a_timeout_of_zero_is_already_spent() {
    let (near, mut far) = connected();
    far.write_all(&frame_of(1)).unwrap();
    let mut framed = FramedStream::new(near, 64);
    framed.set_read_timeout(Some(Duration::ZERO)).unwrap();
    let error = framed.recv().expect_err("nothing is read");
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    // No timeout at all waits again, and nothing was consumed.
    framed.set_read_timeout(None).unwrap();
    assert_eq!(framed.recv().unwrap(), [0x5a]);
}

#[test]
fn a_recv_that_timed_out_in_the_middle_of_a_frame_goes_on_from_there() {
    let (near, mut far) = connected();
    let frame = frame_of(6);
    far.write_all(&frame[..7]).unwrap();
    let mut framed = FramedStream::new(near, 64);
    framed
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(framed.recv().is_err(), "three bytes are missing");
    far.write_all(&frame[7..]).unwrap();
    assert_eq!(framed.recv().unwrap(), [0x5a; 6]);
    assert_eq!(
        framed.current_read_timeout(),
        Some(Duration::from_millis(100))
    );
    // The next frame starts clean.
    far.write_all(&frame_of(2)).unwrap();
    assert_eq!(framed.recv().unwrap(), [0x5a; 2]);
}

#[test]
fn a_handshake_deadline_holds_against_one_byte_at_a_time() {
    let (near, far) = connected();
    let sender = drip(far, frame_of(32), Duration::from_millis(100));
    let identity = Identity::generate().unwrap();
    let method = Noise::builder()
        .identity(identity)
        .initiators(Trust::pinned([]))
        .build()
        .unwrap();
    let mut framed = FramedStream::new(near, MAX_HANDSHAKE_MESSAGE);
    let started = Instant::now();
    let result = drive_messages_until(
        method.respond(None).unwrap(),
        &mut framed,
        started + Duration::from_millis(350),
    );
    let taken = started.elapsed();
    assert!(matches!(result, Err(DriveError::TimedOut)), "{result:?}");
    assert!(taken < Duration::from_secs(2), "ended after {taken:?}");
    drop(framed);
    sender.join().unwrap();
}

#[test]
fn a_frame_above_a_mebibyte_goes_both_ways_when_the_limit_allows_it() {
    const LENGTH: usize = 3 << 20;
    let (near, far) = connected();
    let reading = thread::spawn(move || FramedStream::new(far, LENGTH).recv());
    let mut framed = FramedStream::new(near, LENGTH);
    framed.send(&vec![7u8; LENGTH]).unwrap();
    assert_eq!(reading.join().unwrap().unwrap(), vec![7u8; LENGTH]);
}

#[test]
fn a_frame_above_the_limit_is_refused_and_none_of_it_is_written() {
    let (near, mut far) = connected();
    let mut framed = FramedStream::new(near, 8);
    let error = framed.send(&[0u8; 9]).expect_err("above the limit");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    framed.send(&[1u8; 8]).unwrap();
    framed.into_inner().shutdown(Shutdown::Both).unwrap();
    let mut received = Vec::new();
    far.read_to_end(&mut received).unwrap();
    assert_eq!(received, [&8u32.to_be_bytes()[..], &[1u8; 8]].concat());
}
