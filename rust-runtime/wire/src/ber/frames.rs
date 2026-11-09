//! Reading BER records one at a time from a file, a stream or a buffer
//! (book.md "Reading Records from Files and Streams").
//!
//! A *frame* is one complete top-level TLV with its absolute offset in the
//! input. [`ReadFrames`] reads frames from any [`std::io::Read`] into a
//! reused buffer, reading exactly up to the end of each record, so a file
//! of any size is read in the memory of its largest record. [`SliceFrames`]
//! frames a buffer in memory (or a memory-mapped file) without copying.
//! Both share one walk and follow the contract of the C++ `BerFrameReader`
//! and Java `BerFrames`; `tests/framing` holds the vectors all three pass.

use crate::ber::object::decode_pdu_into;
use crate::ber::reader::{DecodeError, Reader};
use crate::nesting::MAX_DECODE_DEPTH;
use crate::spec::object::Asn1Pdu;
use std::fmt;
use std::io::{self, Read};

/// @brief Limits a framer applies to each record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Largest frame (header, contents and end-of-contents octets)
    /// accepted; a longer record is refused before it is read.
    pub max_frame: usize,
}

impl Default for FrameLimits {
    fn default() -> FrameLimits {
        FrameLimits { max_frame: 64 << 20 }
    }
}

/// @brief One complete top-level BER record, borrowed from the framer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Absolute offset of the record's first octet in the input.
    pub offset: u64,
    /// Tag, length and contents (plus EOC for indefinite length).
    pub bytes: &'a [u8],
}

/// @brief One complete top-level BER record, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    /// Absolute offset of the record's first octet in the input.
    pub offset: u64,
    /// Tag, length and contents (plus EOC for indefinite length).
    pub bytes: Vec<u8>,
}

impl OwnedFrame {
    /// @brief This frame as a borrowed [`Frame`], e.g. for [`decode_frame`].
    pub fn as_frame(&self) -> Frame<'_> {
        Frame { offset: self.offset, bytes: &self.bytes }
    }
}

/// @brief Why [`ReadFrames`] could not return the next frame.
#[derive(Debug)]
pub enum FrameError {
    /// Reading the input failed.
    Io(io::Error),
    /// The input is not a well-formed record (a reason-keyed message, see
    /// book.md); there is no next frame after one.
    Decode(DecodeError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "read error: {e}"),
            FrameError::Decode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            FrameError::Decode(e) => Some(e),
        }
    }
}

impl From<DecodeError> for FrameError {
    fn from(e: DecodeError) -> FrameError {
        FrameError::Decode(e)
    }
}

/// @brief Makes the first `n` octets of the current frame available to
///        [`frame_length`]: a stream source reads exactly that far, a slice
///        source only checks bounds.
trait Source {
    /// @return False when the input ends before `n` octets.
    fn fill(&mut self, n: usize) -> Result<bool, io::Error>;
    fn at(&self, i: usize) -> u8;
    fn available(&self) -> usize;
}

struct SliceSource<'a>(&'a [u8]);

impl Source for SliceSource<'_> {
    fn fill(&mut self, n: usize) -> Result<bool, io::Error> {
        Ok(n <= self.0.len())
    }
    fn at(&self, i: usize) -> u8 {
        self.0[i]
    }
    fn available(&self) -> usize {
        self.0.len()
    }
}

struct ReadSource<'r, R: Read> {
    inner: &'r mut R,
    buf: &'r mut Vec<u8>,
}

impl<R: Read> Source for ReadSource<'_, R> {
    fn fill(&mut self, n: usize) -> Result<bool, io::Error> {
        if self.buf.len() < n {
            // `take` stops the read at exactly n octets in all;
            // `read_to_end` retries interrupted reads and needs no
            // zero-filled buffer.
            let want = (n - self.buf.len()) as u64;
            let got = (&mut *self.inner).take(want).read_to_end(self.buf)?;
            if (got as u64) < want {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn at(&self, i: usize) -> u8 {
        self.buf[i]
    }
    fn available(&self) -> usize {
        self.buf.len()
    }
}

/// The parsed identifier and length octets of one TLV inside a frame.
struct Header {
    /// Frame offset just past the length octets.
    end: usize,
    /// Definite length (0 when indefinite).
    length: u64,
    /// Length octet was 0x80 (X.690 §8.1.3.6).
    indefinite: bool,
    /// The end-of-contents octets 00 00 (X.690 §8.1.5).
    eoc: bool,
}

fn frame_error(message: String, offset: u64) -> FrameError {
    FrameError::Decode(DecodeError::new(message, offset as usize))
}

/// @brief Finds the length of the record at the start of `src`: the walk
///        shared by [`ReadFrames`] and [`SliceFrames`]. Definite contents
///        are skipped without being parsed; an indefinite-length record is
///        closed by walking its nested headers to the matching
///        end-of-contents octets.
/// @param base       Absolute input offset of the frame, for error offsets.
/// @param max_frame  [`FrameLimits::max_frame`].
/// @return The frame length; `None` when the input ends before the
///         record's first octet; or a framing / read error.
/// @see X.690 §8.1.2 (identifier), §8.1.3 (length), §8.1.5 (end-of-contents).
fn frame_length(src: &mut dyn Source, base: u64, max_frame: usize) -> Result<Option<usize>, FrameError> {
    let too_large = || frame_error(format!("frame-too-large: record longer than {max_frame} octets"), base);

    // Make the first n frame octets available: frame-too-large past the
    // limit (checked before reading), truncated when the input ends first.
    let need = |src: &mut dyn Source, n: usize| -> Result<(), FrameError> {
        if n > max_frame {
            return Err(too_large());
        }
        if !src.fill(n).map_err(FrameError::Io)? {
            return Err(frame_error(
                "truncated: input ends inside a record".into(),
                base + src.available() as u64,
            ));
        }
        Ok(())
    };

    let header = |src: &mut dyn Source, pos: usize| -> Result<Header, FrameError> {
        need(src, pos + 1)?;
        let first = src.at(pos);
        let constructed = first & 0x20 != 0;
        let mut p = pos + 1;
        if first & 0x1F == 0x1F {
            let tag_too_long =
                || frame_error("tag-too-long: tag number longer than 5 octets or above 2^31-1".into(), base + pos as u64);
            let mut number: u64 = 0;
            let mut k = 1;
            loop {
                need(src, p + 1)?;
                let b = src.at(p);
                p += 1;
                number = (number << 7) | u64::from(b & 0x7F);
                if b & 0x80 == 0 {
                    break;
                }
                if k == 5 {
                    return Err(tag_too_long());
                }
                k += 1;
            }
            if number > 0x7FFF_FFFF {
                return Err(tag_too_long());
            }
        }
        need(src, p + 1)?;
        let l = src.at(p);
        let eoc = first == 0 && l == 0;
        if l == 0x80 {
            if !constructed {
                return Err(frame_error(
                    "indefinite-primitive: indefinite length on a primitive encoding".into(),
                    base + p as u64,
                ));
            }
            return Ok(Header { end: p + 1, length: 0, indefinite: true, eoc });
        }
        if l & 0x80 != 0 {
            let n = usize::from(l & 0x7F);
            if n > 8 {
                return Err(frame_error(
                    format!("length-field-too-long: length field of {n} octets (at most 8)"),
                    base + p as u64,
                ));
            }
            need(src, p + 1 + n)?;
            let mut length: u64 = 0;
            for i in 0..n {
                length = (length << 8) | u64::from(src.at(p + 1 + i));
            }
            return Ok(Header { end: p + 1 + n, length, indefinite: false, eoc });
        }
        Ok(Header { end: p + 1, length: u64::from(l), indefinite: false, eoc })
    };

    // Skip definite contents: the whole TLV must fit the limit.
    let skip = |src: &mut dyn Source, h: &Header| -> Result<usize, FrameError> {
        let room = (max_frame - h.end.min(max_frame)) as u64;
        if h.length > room {
            return Err(too_large());
        }
        let end = h.end + h.length as usize;
        need(src, end)?;
        Ok(end)
    };

    if !src.fill(1).map_err(FrameError::Io)? {
        return Ok(None);
    }
    let h = header(src, 0)?;
    if !h.indefinite {
        return skip(src, &h).map(Some);
    }
    let mut depth: u32 = 1;
    let mut pos = h.end;
    loop {
        let c = header(src, pos)?;
        if c.eoc {
            pos = c.end;
            depth -= 1;
            if depth == 0 {
                return Ok(Some(pos));
            }
        } else if c.indefinite {
            if depth == MAX_DECODE_DEPTH {
                return Err(frame_error(
                    format!("too-deep: more than {MAX_DECODE_DEPTH} nested indefinite-length levels"),
                    base + pos as u64,
                ));
            }
            depth += 1;
            pos = c.end;
        } else {
            pos = skip(src, &c)?;
        }
    }
}

/// @brief Frames the records of a buffer in memory (or a memory-mapped
///        file) without copying: an iterator of [`Frame`]s borrowing it.
///
/// After a framing error the iterator yields that error once and then
/// ends: it cannot know where the next record starts.
pub struct SliceFrames<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,
    limits: FrameLimits,
    done: bool,
}

impl<'a> SliceFrames<'a> {
    /// @brief Frames `data`, records back to back, with the default limits.
    pub fn new(data: &'a [u8]) -> SliceFrames<'a> {
        SliceFrames { data, pos: 0, base: 0, limits: FrameLimits::default(), done: false }
    }

    /// @brief Sets the limits per record.
    pub fn with_limits(mut self, limits: FrameLimits) -> SliceFrames<'a> {
        self.limits = limits;
        self
    }

    /// @brief Sets the offset of the buffer in a larger input; it is added
    ///        to every frame and error offset.
    pub fn with_base(mut self, base: u64) -> SliceFrames<'a> {
        self.base = base;
        self
    }
}

impl<'a> Iterator for SliceFrames<'a> {
    type Item = Result<Frame<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let offset = self.base + self.pos as u64;
        let rest = &self.data[self.pos..];
        match frame_length(&mut SliceSource(rest), offset, self.limits.max_frame) {
            Ok(Some(len)) => {
                self.pos += len;
                Some(Ok(Frame { offset, bytes: &rest[..len] }))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                match e {
                    FrameError::Decode(e) => Some(Err(e)),
                    FrameError::Io(_) => unreachable!("a slice source never fails to read"),
                }
            }
        }
    }
}

impl std::iter::FusedIterator for SliceFrames<'_> {}

/// @brief Reads BER records one at a time from a [`Read`].
///
/// Memory holds the current record only: its bytes live in a buffer reused
/// for the next one. The framer reads exactly up to the end of each record
/// and does no buffering of its own, so wrap a file in a
/// [`std::io::BufReader`]. After a framing error every later call returns
/// that same error.
///
/// ```no_run
/// use asn1cpp_wire::ber::frames::{decode_frame, ReadFrames};
/// # use asn1cpp_wire::spec::object::Asn1Pdu;
/// # fn handle<T>(_: T) {}
/// # fn run<PsPdu: Asn1Pdu>() -> Result<(), Box<dyn std::error::Error>> {
/// let file = std::io::BufReader::new(std::fs::File::open("capture.etsi")?);
/// let mut frames = ReadFrames::new(file);
/// while let Some(frame) = frames.next_frame()? {   // Err: framing or read error
///     match decode_frame::<PsPdu>(&frame) {
///         Ok(pdu) => handle(pdu),
///         Err(e) => eprintln!("record at byte {}: {e}", frame.offset),  // next record is still read
///     }
/// }
/// # Ok(()) }
/// ```
pub struct ReadFrames<R: Read> {
    inner: R,
    buf: Vec<u8>,
    offset: u64,
    limits: FrameLimits,
    failed: Option<Failure>,
}

/// A stopped framer's error, kept to report again: `io::Error` is not
/// `Clone`, so a read failure is kept as its kind and message.
enum Failure {
    Io(io::ErrorKind, String),
    Decode(DecodeError),
}

impl Failure {
    fn of(e: &FrameError) -> Failure {
        match e {
            FrameError::Io(e) => Failure::Io(e.kind(), e.to_string()),
            FrameError::Decode(e) => Failure::Decode(e.clone()),
        }
    }
    fn error(&self) -> FrameError {
        match self {
            Failure::Io(kind, msg) => FrameError::Io(io::Error::new(*kind, msg.clone())),
            Failure::Decode(e) => FrameError::Decode(e.clone()),
        }
    }
}

impl<R: Read> ReadFrames<R> {
    /// @brief Frames the records of `inner` with the default limits.
    pub fn new(inner: R) -> ReadFrames<R> {
        ReadFrames::with_limits(inner, FrameLimits::default())
    }

    /// @brief Frames the records of `inner` with `limits` per record.
    pub fn with_limits(inner: R, limits: FrameLimits) -> ReadFrames<R> {
        ReadFrames { inner, buf: Vec::new(), offset: 0, limits, failed: None }
    }

    /// @brief Reads the next record.
    /// @return The frame, borrowed until the next call; `None` at the end
    ///         of the input; or a framing / read error.
    pub fn next_frame(&mut self) -> Result<Option<Frame<'_>>, FrameError> {
        if let Some(f) = &self.failed {
            return Err(f.error());
        }
        self.buf.clear();
        let mut src = ReadSource { inner: &mut self.inner, buf: &mut self.buf };
        match frame_length(&mut src, self.offset, self.limits.max_frame) {
            Ok(Some(len)) => {
                let offset = self.offset;
                self.offset += len as u64;
                Ok(Some(Frame { offset, bytes: &self.buf[..len] }))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                self.failed = Some(Failure::of(&e));
                Err(e)
            }
        }
    }

    /// @brief Offset of the next record (the octets consumed so far).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// @brief The input, positioned at the next record.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// @brief An iterator of owned frames (one allocation per record);
    ///        after an error it yields that error once and then ends.
    pub fn into_owned(self) -> OwnedFrames<R> {
        OwnedFrames { frames: self, done: false }
    }
}

/// @brief Iterator of [`OwnedFrame`]s, from [`ReadFrames::into_owned`].
pub struct OwnedFrames<R: Read> {
    frames: ReadFrames<R>,
    done: bool,
}

impl<R: Read> Iterator for OwnedFrames<R> {
    type Item = Result<OwnedFrame, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.frames.next_frame() {
            Ok(Some(f)) => Some(Ok(OwnedFrame { offset: f.offset, bytes: f.bytes.to_vec() })),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl<R: Read> std::iter::FusedIterator for OwnedFrames<R> {}

/// @brief BER-decodes one frame as PDU `T`.
/// @return The value, or the decode error with its offset made absolute
///         (the frame's offset added).
pub fn decode_frame<T: Asn1Pdu>(frame: &Frame<'_>) -> Result<T, DecodeError> {
    let mut v = T::default();
    decode_frame_into(&mut v, frame)?;
    Ok(v)
}

/// @brief In-place form of [`decode_frame`]: decodes into `v`, which is
///        expected to be `Default`-fresh.
pub fn decode_frame_into<T: Asn1Pdu + ?Sized>(v: &mut T, frame: &Frame<'_>) -> Result<(), DecodeError> {
    decode_pdu_into(v, &mut Reader::new(frame.bytes)).map_err(|mut e| {
        e.pos += frame.offset as usize;
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Expect {
        file: String,
        max_frame: usize,
        frames: Vec<(u64, usize)>,
        result: String,
    }

    fn dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/framing")
    }

    fn load() -> Vec<Expect> {
        let text = std::fs::read_to_string(dir().join("framing.vectors")).unwrap();
        text.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                let frames = if c[2] == "-" {
                    Vec::new()
                } else {
                    c[2].split(',')
                        .map(|f| {
                            let (o, n) = f.split_once('+').unwrap();
                            (o.parse().unwrap(), n.parse().unwrap())
                        })
                        .collect()
                };
                Expect {
                    file: c[0].into(),
                    max_frame: if c[1] == "-" { FrameLimits::default().max_frame } else { c[1].parse().unwrap() },
                    frames,
                    result: c[3].into(),
                }
            })
            .collect()
    }

    fn key(e: &DecodeError) -> String {
        format!("error {} {}", e.message.split(':').next().unwrap(), e.pos)
    }

    /// One octet per read, to exercise every partial-read path; counts the
    /// octets handed out.
    struct OneOctet<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for OneOctet<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    /// Runs a ReadFrames to the end in the framing.vectors notation; checks
    /// that the input is left at the end of every frame.
    fn run_read<R: Read>(frames: &mut ReadFrames<R>, data: &[u8], consumed: impl Fn(&ReadFrames<R>) -> u64)
        -> (Vec<(u64, usize)>, String) {
        let mut got = Vec::new();
        loop {
            match frames.next_frame() {
                Ok(Some(f)) => {
                    let (offset, len) = (f.offset, f.bytes.len());
                    assert_eq!(f.bytes, &data[offset as usize..offset as usize + len]);
                    got.push((offset, len));
                    assert_eq!(consumed(frames), offset + len as u64, "input not left at the end of the frame");
                }
                Ok(None) => return (got, "end".into()),
                Err(FrameError::Decode(e)) => {
                    let again = frames.next_frame();
                    assert!(matches!(&again, Err(FrameError::Decode(a)) if *a == e), "error not sticky");
                    return (got, key(&e));
                }
                Err(FrameError::Io(e)) => panic!("read error: {e}"),
            }
        }
    }

    #[test]
    fn shared_framing_vectors() {
        let vectors = load();
        assert!(vectors.len() > 20);
        for v in &vectors {
            let data = std::fs::read(dir().join(&v.file)).unwrap();
            let limits = FrameLimits { max_frame: v.max_frame };

            let mut got = Vec::new();
            let mut result = "end".to_string();
            for f in SliceFrames::new(&data).with_limits(limits) {
                match f {
                    Ok(f) => got.push((f.offset, f.bytes.len())),
                    Err(e) => result = key(&e),
                }
            }
            assert_eq!((&got, &result), (&v.frames, &v.result), "{} (slice)", v.file);

            let mut frames = ReadFrames::with_limits(io::Cursor::new(&data[..]), limits);
            let (got, result) = run_read(&mut frames, &data, |f| f.inner.position());
            assert_eq!((&got, &result), (&v.frames, &v.result), "{} (Read)", v.file);

            let mut frames = ReadFrames::with_limits(OneOctet { data: &data, pos: 0 }, limits);
            let (got, result) = run_read(&mut frames, &data, |f| f.inner.pos as u64);
            assert_eq!((&got, &result), (&v.frames, &v.result), "{} (one octet per read)", v.file);

            let owned: Vec<_> = ReadFrames::with_limits(io::Cursor::new(&data[..]), limits).into_owned().collect();
            let ok: Vec<_> = owned.iter().filter_map(|f| f.as_ref().ok()).map(|f| (f.offset, f.bytes.len())).collect();
            assert_eq!(ok, v.frames, "{} (owned)", v.file);
        }
    }

    #[test]
    fn read_failure_is_an_io_error_and_sticks() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::Other, "disk on fire"))
            }
        }
        let mut frames = ReadFrames::new(Failing);
        assert!(matches!(frames.next_frame(), Err(FrameError::Io(_))));
        let again = frames.next_frame();
        assert!(matches!(&again, Err(FrameError::Io(e)) if e.to_string() == "disk on fire"));
    }

    /// A stream longer than 4 GiB, generated on the fly (never on disk):
    /// 4400 pairs of a 1 MiB OCTET STRING record and a 3-octet INTEGER
    /// record, then a truncated record. The same stream as the C++
    /// `test_ber_frames_large` and the Java `BerFramesTest`.
    struct Generated {
        pos: u64,
    }

    const BIG_HEADER: [u8; 5] = [0x04, 0x83, 0x10, 0x00, 0x00];
    const SMALL: [u8; 3] = [0x02, 0x01, 0x05];
    const TAIL: [u8; 3] = [0x04, 0x05, 0x00];
    const BIG: u64 = 5 + (1 << 20);
    const PAIR: u64 = BIG + 3;
    const PAIRS: u64 = 4400;
    const TOTAL: u64 = PAIRS * PAIR + 3;

    impl Read for Generated {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut n = 0;
            while n < buf.len() && self.pos < TOTAL {
                let q = self.pos % PAIR;
                if self.pos >= PAIRS * PAIR {
                    buf[n] = TAIL[(self.pos - PAIRS * PAIR) as usize];
                } else if q < 5 {
                    buf[n] = BIG_HEADER[q as usize];
                } else if q < BIG {
                    let run = ((BIG - q) as usize).min(buf.len() - n);
                    buf[n..n + run].fill(0);
                    n += run;
                    self.pos += run as u64;
                    continue;
                } else {
                    buf[n] = SMALL[(q - BIG) as usize];
                }
                n += 1;
                self.pos += 1;
            }
            Ok(n)
        }
    }

    /// Peak resident memory of this process in MiB (Linux `VmHWM`).
    fn peak_mib() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
        line.split_whitespace().nth(1)?.parse::<u64>().ok().map(|kb| kb / 1024)
    }

    #[test]
    fn stream_longer_than_four_gib() {
        let mut frames = ReadFrames::new(Generated { pos: 0 });
        let mut count: u64 = 0;
        let err = loop {
            match frames.next_frame() {
                Ok(Some(f)) => {
                    let want = (count / 2) * PAIR + if count % 2 == 1 { BIG } else { 0 };
                    let len = if count % 2 == 1 { 3 } else { BIG as usize };
                    assert_eq!((f.offset, f.bytes.len()), (want, len), "frame {count}");
                    count += 1;
                }
                Ok(None) => panic!("stream ended without the truncated tail"),
                Err(FrameError::Decode(e)) => break e,
                Err(FrameError::Io(e)) => panic!("{e}"),
            }
        };
        assert_eq!(count, 2 * PAIRS);
        assert!(err.message.starts_with("truncated:"), "{err}");
        assert_eq!(err.pos as u64, TOTAL);
        if let Some(mib) = peak_mib() {
            // Other tests run in this process too; the framer itself holds
            // one record (1 MiB).
            assert!(mib < 512, "peak memory {mib} MiB");
        }
    }

    /// `Ints ::= SEQUENCE OF INTEGER`, the shape RustBackend emits for a
    /// named SEQUENCE OF, as a PDU to decode frames into.
    #[derive(Debug, Clone, Default, PartialEq)]
    struct Ints(Vec<crate::integer::Integer>);

    impl crate::spec::object::Asn1SeqOf for Ints {
        fn natural_tag(&self) -> crate::ber::tag::Tag { crate::ber::sequence::SEQUENCE_TAG }
        fn own_xer_name(&self) -> &'static str { "Ints" }
        fn len(&self) -> usize { self.0.len() }
        fn get(&self, index: usize) -> crate::spec::object::MemberRef<'_> {
            crate::spec::object::AsMemberRef::as_member_ref(&self.0[index])
        }
        fn push_default_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
            self.0.push(crate::integer::Integer::default());
            crate::spec::object::AsMemberRef::as_member_ref_mut(self.0.last_mut().unwrap())
        }
        fn elem_natural_xer_name(&self, index: usize) -> &'static str {
            crate::spec::object::AsMemberRef::own_element_xer_name(&self.0[index])
        }
        fn elem_xer_instruction(&self) -> crate::spec::object::XerInstruction {
            crate::spec::object::XerInstruction::Default
        }
    }

    impl crate::spec::object::AsMemberRef for Ints {
        fn as_member_ref(&self) -> crate::spec::object::MemberRef<'_> { crate::spec::object::MemberRef::SeqOf(self) }
        fn as_member_ref_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
            crate::spec::object::MemberRefMut::SeqOf(self)
        }
        fn own_element_xer_name(&self) -> &'static str { "Ints" }
    }

    impl Asn1Pdu for Ints {}

    #[test]
    fn decode_frame_rebases_errors_and_the_stream_goes_on() {
        // Two records after 100 octets of other input; the INTEGER of the
        // second has no contents octets, which X.690 §8.3.1 forbids.
        let data = [0x30, 0x03, 0x02, 0x01, 0x05, 0x30, 0x02, 0x02, 0x00];
        let mut frames = SliceFrames::new(&data).with_base(100);
        let a = frames.next().unwrap().unwrap();
        let v: Ints = decode_frame(&a).unwrap();
        assert_eq!(v.0, vec![crate::integer::Integer(5)]);
        let b = frames.next().unwrap().unwrap();
        assert_eq!(b.offset, 105);
        let e = decode_frame::<Ints>(&b).unwrap_err();
        assert!(e.pos >= 105, "{e}");
        assert!(frames.next().is_none());
    }
}
