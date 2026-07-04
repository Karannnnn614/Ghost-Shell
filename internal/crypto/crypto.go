// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package crypto provides at-rest encryption for cast files: a framed
// AES-256-GCM stream so a recording on disk is opaque to cat/strings/grep and
// is readable only with the key.
//
// File layout (current, V2):
//
//	"TTEC2\n"
//	[16-byte random stream id]
//	[4-byte big-endian frame length][12-byte nonce][ciphertext + 16-byte tag]
//	...
//
// Each Write to the writer becomes one frame with a fresh random nonce. Every
// frame is authenticated with additional data (AAD) of stream-id || frame-index,
// so a frame cannot be reordered, duplicated, truncated mid-stream, or spliced
// in from another recording (which has a different stream id) without failing
// authentication. The reader decrypts frames in order; a truncated or corrupt
// trailing frame is treated as end-of-stream (a recording whose daemon died
// mid-write is still readable up to the last complete frame).
//
// Legacy V1 files ("TTEC1\n"; frames with no stream id and no AAD) remain
// readable via NewReader for backward compatibility. New files are always V2.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic marks a legacy V1 encrypted cast file (frames with no AAD binding).
const Magic = "TTEC1\n"

// MagicV2 marks a V2 encrypted cast file: a 16-byte stream id follows the magic
// and every frame is bound by AAD (stream id || frame index). MagicV2 is the
// same byte length as Magic so detection reads a fixed-size prefix.
const MagicV2 = "TTEC2\n"

// streamIDSize is the length of the per-file random stream id in a V2 file.
const streamIDSize = 16

// aadCounterSize is the big-endian frame index appended to the stream id to form
// each frame's additional authenticated data.
const aadCounterSize = 8

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// maxFrameSize bounds a single on-disk frame (nonce + ciphertext + tag). It
// matches the largest expected PTY write chunk and is enforced symmetrically:
// the writer refuses to emit a larger frame and the reader rejects a larger
// length prefix as corrupt/truncated.
const maxFrameSize = 1 << 20 // 1 MiB

// ErrCorruptFrame reports that a frame failed GCM authentication/decryption
// (tampering, reordering, cross-file splicing, or wrong key) rather than ending
// cleanly. The reader still returns io.EOF from Read to stop the stream at the
// last good frame, but records this cause; callers can retrieve it via
// DecReader.Err (e.g. through the Errer interface) to distinguish corruption
// from a clean truncation.
var ErrCorruptFrame = errors.New("crypto: frame failed authentication (tampered, reordered, or wrong key)")

// MagicVersion reports the encryption version implied by a file's leading bytes:
// 2 for a V2 file, 1 for a legacy V1 file, or 0 if the bytes are not an
// encrypted-cast magic (i.e. the file is plaintext). Pass at least the first
// len(Magic) bytes; V1 and V2 magics are the same length.
func MagicVersion(prefix []byte) int {
	switch {
	case len(prefix) >= len(MagicV2) && string(prefix[:len(MagicV2)]) == MagicV2:
		return 2
	case len(prefix) >= len(Magic) && string(prefix[:len(Magic)]) == Magic:
		return 1
	default:
		return 0
	}
}

// GenerateKey returns a new random 32-byte key.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type encWriter struct {
	w        io.Writer
	gcm      cipher.AEAD
	streamID []byte // nil for V1 (no AAD binding)
	counter  uint64 // index of the next frame, bound into its AAD (V2 only)
}

// NewWriter writes a V2 encrypted stream (magic, a random stream id, then a
// frame per Write) and returns the framing writer.
//
// Framing contract: every Write produces exactly one self-contained frame
// ([4-byte length][12-byte nonce][ciphertext+tag]) with a fresh random nonce
// and AAD binding it to this file and its position, flushed to the underlying
// writer before Write returns. There is no internal buffering and no Close/flush
// step: a recording is complete after each Write, so a daemon that dies between
// Writes leaves a stream that the reader can decrypt up to the last fully
// written frame (the trailing partial frame is treated as a clean truncation).
// A Write must not exceed maxFrameSize bytes of plaintext; an empty Write is a
// no-op and emits no frame.
func NewWriter(w io.Writer, key []byte) (io.Writer, error) {
	return newWriter(w, key, 2)
}

// newWriter builds a writer for the given format version (2 = stream-id + AAD,
// 1 = legacy no-AAD). Version 1 exists only to exercise the backward-compatible
// read path in tests; production always writes version 2 via NewWriter.
func newWriter(w io.Writer, key []byte, version int) (io.Writer, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ew := &encWriter{w: w, gcm: gcm}
	if version == 2 {
		if _, err := io.WriteString(w, MagicV2); err != nil {
			return nil, err
		}
		sid := make([]byte, streamIDSize)
		if _, err := rand.Read(sid); err != nil {
			return nil, err
		}
		if _, err := w.Write(sid); err != nil {
			return nil, err
		}
		ew.streamID = sid
	} else {
		if _, err := io.WriteString(w, Magic); err != nil {
			return nil, err
		}
	}
	return ew, nil
}

// frameAAD returns the additional authenticated data for the frame at the
// current counter: stream id || 8-byte big-endian frame index. It returns nil
// for a V1 writer (no binding).
func frameAAD(streamID []byte, counter uint64) []byte {
	if streamID == nil {
		return nil
	}
	aad := make([]byte, len(streamID)+aadCounterSize)
	copy(aad, streamID)
	binary.BigEndian.PutUint64(aad[len(streamID):], counter)
	return aad
}

func (e *encWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	ct := e.gcm.Seal(nil, nonce, p, frameAAD(e.streamID, e.counter))
	// Guard the uint32 length prefix: a single Write large enough to overflow
	// the 4-byte field (or merely exceed the reader's cap) would otherwise emit
	// an oversized/wrapped frame the reader rejects. Enforce the cap up front.
	frameLen := len(nonce) + len(ct)
	if frameLen > maxFrameSize {
		return 0, fmt.Errorf("crypto: frame size %d exceeds max %d", frameLen, maxFrameSize)
	}
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(frameLen))
	if _, err := e.w.Write(lenbuf[:]); err != nil {
		return 0, err
	}
	if _, err := e.w.Write(nonce); err != nil {
		return 0, err
	}
	if _, err := e.w.Write(ct); err != nil {
		return 0, err
	}
	e.counter++ // advance only after a fully written frame
	return len(p), nil
}

// Errer is implemented by the reader returned from NewReader/NewReaderV2. After
// Read has returned io.EOF, Err reports whether the stream ended because a frame
// failed authentication (ErrCorruptFrame: tampering, reordering, splicing, or
// wrong key) rather than cleanly. Callers that only have the io.Reader can
// type-assert to this interface.
type Errer interface {
	Err() error
}

// DecReader yields the decrypted plaintext stream. It is the concrete type
// returned by NewReader/NewReaderV2; callers normally use it through io.Reader
// and may type-assert to Errer (or *DecReader) to inspect Err after EOF.
type DecReader struct {
	r        io.Reader
	gcm      cipher.AEAD
	buf      []byte
	err      error  // set to ErrCorruptFrame when a frame fails authentication
	streamID []byte // nil for V1; set (len streamIDSize) once read for V2
	needSID  bool   // V2: read the stream id before the first frame
	counter  uint64 // index of the next frame, bound into its AAD (V2 only)
}

// NewReader returns a reader yielding the decrypted plaintext of a legacy V1
// stream. The caller must have already consumed the magic prefix. The returned
// reader's dynamic type is *DecReader, which implements Errer.
func NewReader(r io.Reader, key []byte) (io.Reader, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &DecReader{r: r, gcm: gcm}, nil
}

// NewReaderV2 returns a reader for a V2 stream. The caller must have already
// consumed the magic prefix; the 16-byte stream id is read lazily on the first
// Read (so a file truncated before it is treated as a clean EOF), and each frame
// is verified with AAD binding it to that stream id and its position.
func NewReaderV2(r io.Reader, key []byte) (io.Reader, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &DecReader{r: r, gcm: gcm, needSID: true}, nil
}

// Err returns ErrCorruptFrame if the stream stopped because a frame failed GCM
// authentication (tampering, reordering, splicing, or wrong key), or nil for a
// clean end/truncation. It is meaningful only after Read has reported io.EOF.
func (d *DecReader) Err() error { return d.err }

func (d *DecReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.needSID {
			sid := make([]byte, streamIDSize)
			if _, err := io.ReadFull(d.r, sid); err != nil {
				return 0, io.EOF // truncated before/within the stream id
			}
			d.streamID = sid
			d.needSID = false
		}
		var lenbuf [4]byte
		if _, err := io.ReadFull(d.r, lenbuf[:]); err != nil {
			return 0, io.EOF // clean end or truncated length: stop
		}
		flen := binary.BigEndian.Uint32(lenbuf[:])
		if int(flen) < d.gcm.NonceSize() {
			return 0, io.EOF
		}
		if flen > maxFrameSize {
			return 0, io.ErrUnexpectedEOF // corrupt or truncated file
		}
		frame := make([]byte, flen)
		if _, err := io.ReadFull(d.r, frame); err != nil {
			return 0, io.EOF // truncated trailing frame: stop at last complete one
		}
		ns := d.gcm.NonceSize()
		pt, err := d.gcm.Open(nil, frame[:ns], frame[ns:], frameAAD(d.streamID, d.counter))
		if err != nil {
			// Authentication failure (tampering, reordering, splicing, or wrong
			// key) — distinct from a clean truncation. Record the cause so callers
			// can tell the two apart via Err, while still stopping the stream with
			// io.EOF so a recording remains readable up to the last good frame.
			d.err = ErrCorruptFrame
			return 0, io.EOF
		}
		d.counter++
		d.buf = pt
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}
