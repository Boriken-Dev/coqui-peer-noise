use core::time::Duration;
use std::io::{self, Read, Write};

use coqui_peer::{MessageTransport, ReadTimeout, WriteTimeout, write_frame};

/// The longest handshake message: the second, 96 bytes. All three have a fixed length.
pub const MAX_HANDSHAKE_MESSAGE: usize = 96;

/// A byte stream as a message transport whose frames are refused by their declared length before
/// any of the body is read or held, which `coqui_peer::drive_stream` does only at `MAX_MESSAGE`.
/// Frames are coqui-peer's: four big-endian length bytes, then the message.
///
/// Run a handshake with `coqui_peer::drive_messages` (or `drive_messages_until`, whose deadline
/// goes through this type's timeouts) over one, at [`MAX_HANDSHAKE_MESSAGE`], then raise the limit
/// with [`set_max_message`](FramedStream::set_max_message) for records.
#[derive(Debug)]
pub struct FramedStream<S> {
    stream: S,
    max_message: usize,
}

impl<S> FramedStream<S> {
    /// `stream`, refusing a frame longer than `max_message` bytes.
    pub const fn new(stream: S, max_message: usize) -> Self {
        Self {
            stream,
            max_message,
        }
    }

    /// The limit from now on.
    pub const fn set_max_message(&mut self, max_message: usize) {
        self.max_message = max_message;
    }

    /// The stream underneath, with nothing buffered in this type.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> MessageTransport for FramedStream<S> {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        write_frame(&mut self.stream, message)
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut prefix = [0u8; 4];
        self.stream.read_exact(&mut prefix)?;
        let length = u64::from(u32::from_be_bytes(prefix));
        if usize::try_from(length)
            .ok()
            .is_none_or(|length| length > self.max_message)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut message = Vec::new();
        let read = (&mut self.stream).take(length).read_to_end(&mut message)?;
        if u64::try_from(read).ok() != Some(length) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(message)
    }
}

impl<S: ReadTimeout> ReadTimeout for FramedStream<S> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }
}

impl<S: WriteTimeout> WriteTimeout for FramedStream<S> {
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
}
