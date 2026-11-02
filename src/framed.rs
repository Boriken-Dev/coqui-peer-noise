use core::cell::Cell;
use core::time::Duration;
use std::io::{self, Read, Write};
use std::time::Instant;

use coqui_peer::{MessageTransport, ReadTimeout, WriteTimeout};

/// The longest handshake message: the second, 96 bytes. All three have a fixed length.
pub const MAX_HANDSHAKE_MESSAGE: usize = 96;

const PREFIX: usize = 4;

/// A [`ReadTimeout`] that can say what it is set to, which `ReadTimeout` itself cannot.
/// [`PairingSession::respond`](crate::PairingSession::respond) waits for the smaller of this and
/// its own bound, rather than replacing a timeout the caller set.
pub trait CurrentReadTimeout: ReadTimeout {
    /// The timeout set now: `None` for none, and for a transport that cannot time out.
    fn current_read_timeout(&self) -> Option<Duration>;
}

/// A byte stream as a message transport whose frames are refused by their declared length before
/// any of the body is read or held, which `coqui_peer::drive_stream` does only at `MAX_MESSAGE`.
/// Frames are coqui-peer's: four big-endian length bytes, then the message.
///
/// Run a handshake with `coqui_peer::drive_messages` (or `drive_messages_until`, whose deadline
/// goes through this type's timeouts) over one, at [`MAX_HANDSHAKE_MESSAGE`], then raise the limit
/// with [`set_max_message`](FramedStream::set_max_message) for records.
///
/// A read timeout set here bounds a whole [`recv`](MessageTransport::recv), however many reads of
/// the stream that takes, so a peer sending one byte at a time cannot outlast it. A timeout set on
/// the stream directly applies per read. A `recv` that timed out keeps what it read of its frame,
/// and the next goes on from there.
#[derive(Debug)]
pub struct FramedStream<S> {
    stream: S,
    max_message: usize,
    read_timeout: Cell<Option<Duration>>,
    pending: Vec<u8>,
}

impl<S> FramedStream<S> {
    /// `stream`, refusing a frame longer than `max_message` bytes, in either direction.
    pub const fn new(stream: S, max_message: usize) -> Self {
        Self {
            stream,
            max_message,
            read_timeout: Cell::new(None),
            pending: Vec::new(),
        }
    }

    /// The limit from now on. Nothing but this limit and the length field's 2^32 - 1 bounds a frame.
    pub const fn set_max_message(&mut self, max_message: usize) {
        self.max_message = max_message;
    }

    /// The stream underneath. This type holds nothing of it but what a timed-out
    /// [`recv`](MessageTransport::recv) read of an unfinished frame.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// `stream`, each of whose reads waits at most what is left until `until`.
struct Until<'a, S> {
    stream: &'a mut S,
    until: Option<Instant>,
}

impl<S: Read + ReadTimeout> Read for Until<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(until) = self.until {
            let left = until
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.stream.set_read_timeout(Some(left))?;
        }
        self.stream.read(buffer)
    }
}

impl<S: Read + Write + ReadTimeout> MessageTransport for FramedStream<S> {
    /// # Errors
    ///
    /// `InvalidInput` above the limit, with nothing written; otherwise the stream's error.
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        let length = u32::try_from(message.len())
            .ok()
            .filter(|_| message.len() <= self.max_message)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.stream.write_all(&length.to_be_bytes())?;
        self.stream.write_all(message)?;
        self.stream.flush()
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let until = self
            .read_timeout
            .get()
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let mut reader = Until {
            stream: &mut self.stream,
            until,
        };
        let read = |reader: &mut Until<'_, S>, pending: &mut Vec<u8>, whole: u64| {
            let missing = whole.saturating_sub(pending.len() as u64);
            reader.take(missing).read_to_end(pending)?;
            if pending.len() as u64 >= whole {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        };
        read(&mut reader, &mut self.pending, PREFIX as u64)?;
        let length = u32::from_be_bytes([
            self.pending[0],
            self.pending[1],
            self.pending[2],
            self.pending[3],
        ]);
        if usize::try_from(length)
            .ok()
            .is_none_or(|length| length > self.max_message)
        {
            self.pending.clear();
            return Err(io::ErrorKind::InvalidData.into());
        }
        read(
            &mut reader,
            &mut self.pending,
            PREFIX as u64 + u64::from(length),
        )?;
        let mut message = core::mem::take(&mut self.pending);
        message.drain(..PREFIX);
        Ok(message)
    }
}

impl<S: ReadTimeout> ReadTimeout for FramedStream<S> {
    /// Bounds each whole `recv` from now on. A timeout of zero is already spent: `recv` reports
    /// `TimedOut` and reads nothing, and the stream, which may refuse a zero, is not told.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout.set(timeout);
        match timeout {
            Some(timeout) if timeout.is_zero() => Ok(()),
            timeout => self.stream.set_read_timeout(timeout),
        }
    }
}

impl<S: ReadTimeout> CurrentReadTimeout for FramedStream<S> {
    fn current_read_timeout(&self) -> Option<Duration> {
        self.read_timeout.get()
    }
}

impl<S: WriteTimeout> WriteTimeout for FramedStream<S> {
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
}
