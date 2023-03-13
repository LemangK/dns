//! Reading strings from the DNS wire protocol.
#![allow(dead_code)]

use byteorder::ReadBytesExt;
use bytes::{BufMut, BytesMut};
use crate::DomainString;
use tracing::*;
use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Cursor, ErrorKind};

/// Domain names in the DNS protocol are encoded as **Labels**, which are
/// segments of ASCII characters prefixed by their length. When written out,
/// each segment is followed by a dot.
///
/// The maximum length of a segment is 255 characters.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Labels {
    segments: Vec<(u8, DomainString)>,
}

#[cfg(feature = "with_idna")]
fn label_to_ascii(label: &str) -> Result<DomainString, unic_idna::Errors> {
    let flags = unic_idna::Flags {
        use_std3_ascii_rules: false,
        transitional_processing: false,
        verify_dns_length: true,
    };
    let s = unic_idna::to_ascii(label, flags)?;
    Ok(s.into())
}

#[cfg(not(feature = "with_idna"))]
fn label_to_ascii(label: &str) -> Result<DomainString, ()> {
    Ok(DomainString::from(label))
}

impl Labels {
    /// Creates a new empty set of labels, which represent the root of the DNS
    /// as a domain with no name.
    pub fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn verify(input: &str) -> bool {
        for label in input.split('.') {
            if label.is_empty() {
                continue;
            }
            if !u8::try_from(label.len()).is_ok() {
                return false;
            }
        }
        true
    }

    pub fn encode_with_io(input: &str) -> io::Result<Self> {
        let mut segments = Vec::new();
        Self::encode(input, &mut segments).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(Self { segments })
    }

    pub fn encode_to_buf(input: &str, buf: &mut BytesMut) -> io::Result<()> {
        for label in input.split('.') {
            if label.is_empty() {
                continue;
            }

            let label_idn = label_to_ascii(label).map_err(|e| {
                warn!("Could not encode label {:?}: {:?}", label, e);
                io::Error::new(ErrorKind::Other, label)
            })?;

            match u8::try_from(label_idn.len()) {
                Ok(length) => {
                    buf.put_u8(length);
                    buf.put_slice(label_idn.as_bytes());
                }
                Err(e) => {
                    warn!("Could not encode label {:?}: {}", label, e);
                    return Err(io::Error::new(ErrorKind::Other, label));
                }
            }
        }
        buf.put_u8(0); // terminate the string
        Ok(())
    }

    /// Encodes the given input string as labels. If any segment is too long,
    /// returns that segment as an error.
    pub fn encode<'a>(input: &'a str, segments: &'a mut Vec<(u8, DomainString)>) -> Result<(), &'a str> {
        for label in input.split('.') {
            if label.is_empty() {
                continue;
            }

            let label_idn = label_to_ascii(label).map_err(|e| {
                warn!("Could not encode label {:?}: {:?}", label, e);
                label
            })?;

            match u8::try_from(label_idn.len()) {
                Ok(length) => {
                    segments.push((length, label_idn));
                }
                Err(e) => {
                    warn!("Could not encode label {:?}: {}", label, e);
                    return Err(label);
                }
            }
        }

        Ok(())
    }

    /// Returns the number of segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns a new set of labels concatenating two names.
    pub fn extend(&self, other: &Self) -> Self {
        let mut segments = self.segments.clone();
        segments.extend_from_slice(&other.segments);
        Self { segments }
    }

    pub fn unpack(buf: &[u8]) -> io::Result<(Labels, u16)> {
        let mut labels = Labels {
            segments: Vec::new(),
        };
        let bytes_read =
            read_string_recursive(&mut labels, &mut Cursor::new(buf), &mut Vec::new())?;
        Ok((labels, bytes_read))
    }

    /// Write a domain name.
    ///
    /// The names being queried are written with one byte slice per
    /// domain segment, preceded by each segment’s length, with the
    /// whole thing ending with a segment of zero length.
    ///
    /// So “dns.lookup.dog” would be encoded as:
    /// “3, dns, 6, lookup, 3, dog, 0”.
    pub fn pack(&self, buf: &mut BytesMut) -> io::Result<()> {
        for (length, label) in &self.segments {
            buf.put_u8(*length);
            buf.put_slice(label.as_bytes());
        }

        buf.put_u8(0); // terminate the string
        Ok(())
    }
}

impl fmt::Display for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (_, segment) in &self.segments {
            write!(f, "{}.", segment)?;
        }

        Ok(())
    }
}

const RECURSION_LIMIT: usize = 8;

/// Reads bytes from the given cursor into the given buffer, using the list of
/// recursions to track backtracking positions. Returns the count of bytes
/// that had to be read to produce the string, including the bytes to signify
/// backtracking, but not including the bytes read _during_ backtracking.
#[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
fn read_string_recursive(
    labels: &mut Labels,
    c: &mut Cursor<&[u8]>,
    recursions: &mut Vec<u16>,
) -> io::Result<u16> {
    let mut bytes_read = 0;

    loop {
        let byte = c.read_u8()?;
        bytes_read += 1;

        if byte == 0 {
            break;
        } else if byte >= 0b_1100_0000 {
            let name_one = byte - 0b1100_0000;
            let name_two = c.read_u8()?;
            bytes_read += 1;
            let offset = u16::from_be_bytes([name_one, name_two]);

            if recursions.contains(&offset) {
                warn!("Hit previous offset ({}) decoding string", offset);
                return Err(io::Error::new(ErrorKind::Other, "TooMuchRecursion"));
            }

            recursions.push(offset);

            if recursions.len() >= RECURSION_LIMIT {
                warn!("Hit recursion limit ({}) decoding string", RECURSION_LIMIT);
                return Err(io::Error::new(ErrorKind::Other, "TooMuchRecursion"));
            }

            trace!("Backtracking to offset {}", offset);
            let new_pos = c.position();
            c.set_position(u64::from(offset));

            read_string_recursive(labels, c, recursions)?;

            trace!("Coming back to {:?}", new_pos);
            c.set_position(new_pos);
            break;
        }
        // Otherwise, treat the byte as the length of a label, and read that
        // many characters.
        else {
            let mut string = DomainString::new();
            for _ in 0..byte {
                let c = c.read_u8()?;
                bytes_read += 1;
                string.push(c as char);
            }
            labels.segments.push((byte, string));
        }
    }

    Ok(bytes_read)
}
