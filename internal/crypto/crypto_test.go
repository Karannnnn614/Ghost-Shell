package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// BenchmarkEncryptThroughput measures steady-state AES-256-GCM framing
// throughput for a recorder-sized chunk. The reported MB/s (hardware AES-NI,
// typically multiple GB/s) dwarfs real terminal data rates (KB/s–MB/s) by orders
// of magnitude, so encryption is never the recording bottleneck — moving it off
// the write path would add a channel hop and a data-durability risk for no
// measurable gain. See OPTIMIZATIONS.md.
func BenchmarkEncryptThroughput(b *testing.B) {
	key := make([]byte, KeySize)
	w, err := NewWriter(io.Discard, key)
	if err != nil {
		b.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("x"), 32*1024) // one recorder Read (<= ScrollBuffer)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}

// frameOffsets walks the framed output (after the V2 magic + stream id) and
// returns, for each frame, the absolute offset of its 4-byte length prefix.
func frameOffsets(t *testing.T, b []byte) []int {
	t.Helper()
	if !bytes.HasPrefix(b, []byte(MagicV2)) {
		t.Fatalf("missing V2 magic prefix")
	}
	var offs []int
	off := len(MagicV2) + streamIDSize
	for off+4 <= len(b) {
		flen := int(binary.BigEndian.Uint32(b[off : off+4]))
		offs = append(offs, off)
		off += 4 + flen
	}
	if off != len(b) {
		t.Fatalf("frame walk did not consume buffer exactly: ended at %d of %d", off, len(b))
	}
	return offs
}

// openV2 consumes the V2 magic from b and returns a reader over the rest.
func openV2(t *testing.T, b, key []byte) io.Reader {
	t.Helper()
	r := bytes.NewReader(b)
	magic := make([]byte, len(MagicV2))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != MagicV2 {
		t.Fatalf("magic read: %v %q", err, magic)
	}
	dr, err := NewReaderV2(r, key)
	if err != nil {
		t.Fatalf("NewReaderV2: %v", err)
	}
	return dr
}

// erErr is a tiny helper for error messages where the Errer assertion may fail.
func erErr(r io.Reader) error {
	if er, ok := r.(Errer); ok {
		return er.Err()
	}
	return nil
}

func TestRoundTripMultiChunk(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var buf bytes.Buffer
	w, err := NewWriter(&buf, key)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	chunks := []string{
		`{"version":2,"width":80,"height":24}` + "\n",
		`[0.1, "o", "hello\r\n"]` + "\n",
		`[0.2, "o", "world\r\n"]` + "\n",
	}
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	// On-disk bytes must be opaque: the plaintext must not appear.
	if bytes.Contains(buf.Bytes(), []byte("hello")) {
		t.Fatal("plaintext 'hello' found in ciphertext output")
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte(MagicV2)) {
		t.Fatal("missing V2 magic prefix")
	}
	if MagicVersion(buf.Bytes()) != 2 {
		t.Fatalf("MagicVersion = %d, want 2", MagicVersion(buf.Bytes()))
	}

	dr := openV2(t, buf.Bytes(), key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := strings.Join(chunks, "")
	if string(got) != want {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestV1BackwardCompatible writes a legacy V1 stream (no stream id, no AAD) and
// confirms NewReader still decrypts it, so recordings made before the V2 format
// remain readable.
func TestV1BackwardCompatible(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, err := newWriter(&buf, key, 1) // test-only legacy writer
	if err != nil {
		t.Fatalf("newWriter v1: %v", err)
	}
	chunks := []string{"old recording line one\n", "old recording line two\n"}
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if !bytes.HasPrefix(buf.Bytes(), []byte(Magic)) {
		t.Fatal("V1 writer must emit the TTEC1 magic")
	}
	if MagicVersion(buf.Bytes()) != 1 {
		t.Fatalf("MagicVersion = %d, want 1", MagicVersion(buf.Bytes()))
	}

	// V1 read path: consume magic, then NewReader (no stream id, nil AAD).
	r := bytes.NewReader(buf.Bytes())
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		t.Fatalf("magic read: %v", err)
	}
	dr, _ := NewReader(r, key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != strings.Join(chunks, "") {
		t.Fatalf("V1 round-trip mismatch: got %q", got)
	}
}

func TestTruncatedTrailingFrameIsEOF(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	_, _ = w.Write([]byte("first frame intact\n"))
	_, _ = w.Write([]byte("second frame will be truncated\n"))

	full := buf.Bytes()
	// Chop the last 5 bytes to simulate a daemon dying mid-write.
	truncated := full[:len(full)-5]

	dr := openV2(t, truncated, key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("expected nil error (truncation -> EOF), got %v", err)
	}
	if !strings.Contains(string(got), "first frame intact") {
		t.Fatalf("first complete frame should be recovered, got %q", got)
	}
	if strings.Contains(string(got), "truncated") {
		t.Fatalf("partial trailing frame should be dropped, got %q", got)
	}
	if er, ok := dr.(Errer); !ok || er.Err() != nil {
		t.Fatalf("clean truncation must not report an error, got %v", erErr(dr))
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, k1)
	_, _ = w.Write([]byte("secret session data\n"))

	dr := openV2(t, buf.Bytes(), k2)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("Read should stop with EOF, not surface a hard error: %v", err)
	}
	if strings.Contains(string(got), "secret") {
		t.Fatal("wrong key must not decrypt plaintext")
	}
	if er, ok := dr.(Errer); !ok || !errors.Is(er.Err(), ErrCorruptFrame) {
		t.Fatalf("expected ErrCorruptFrame after wrong-key read, got %v", erErr(dr))
	}
}

// TestMidStreamTamperStopsAtFrame flips a byte in a NON-trailing frame and
// asserts decryption stops at that frame (proving mid-stream authentication, not
// just trailing-frame handling) and that the failure is reported via Err.
func TestMidStreamTamperStopsAtFrame(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	_, _ = w.Write([]byte("frame one stays intact\n"))
	_, _ = w.Write([]byte("frame two gets corrupted\n"))
	_, _ = w.Write([]byte("frame three after the bad one\n"))

	out := buf.Bytes()
	offs := frameOffsets(t, out)
	if len(offs) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(offs))
	}
	// Flip a byte inside the second frame's ciphertext/tag region (skip its
	// 4-byte length prefix so the framing still parses and we exercise the GCM
	// Open path rather than a length error).
	tamper := offs[1] + 4 + 6
	mutated := make([]byte, len(out))
	copy(mutated, out)
	mutated[tamper] ^= 0xFF

	dr := openV2(t, mutated, key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("Read should stop with EOF: %v", err)
	}
	if !strings.Contains(string(got), "frame one stays intact") {
		t.Fatalf("frame before tamper should decrypt, got %q", got)
	}
	if strings.Contains(string(got), "frame two") {
		t.Fatalf("tampered frame must not decrypt, got %q", got)
	}
	if strings.Contains(string(got), "frame three") {
		t.Fatalf("stream must stop at the tampered frame, not resync, got %q", got)
	}
	if er, ok := dr.(Errer); !ok || !errors.Is(er.Err(), ErrCorruptFrame) {
		t.Fatalf("mid-stream tamper must report ErrCorruptFrame, got %v (ok=%v)", erErr(dr), ok)
	}
}

// TestFrameReorderDetected swaps two whole frames and asserts the AAD frame-index
// binding makes the stream fail authentication (V2 anti-reorder property).
func TestFrameReorderDetected(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	_, _ = w.Write([]byte("frame zero\n"))
	_, _ = w.Write([]byte("frame one\n"))
	_, _ = w.Write([]byte("frame two\n"))

	out := buf.Bytes()
	offs := frameOffsets(t, out)
	if len(offs) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(offs))
	}
	frame := func(i int) []byte {
		end := len(out)
		if i+1 < len(offs) {
			end = offs[i+1]
		}
		return append([]byte{}, out[offs[i]:end]...)
	}
	// Reassemble header + frame1 + frame0 + frame2 (swap the first two).
	reordered := append([]byte{}, out[:offs[0]]...)
	reordered = append(reordered, frame(1)...)
	reordered = append(reordered, frame(0)...)
	reordered = append(reordered, frame(2)...)

	dr := openV2(t, reordered, key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("Read should stop with EOF: %v", err)
	}
	// frame1 was sealed with AAD index 1 but now appears at index 0, so the very
	// first Open fails: no frame should decrypt.
	if len(got) != 0 {
		t.Fatalf("reordered stream must not decrypt any frame, got %q", got)
	}
	if er, ok := dr.(Errer); !ok || !errors.Is(er.Err(), ErrCorruptFrame) {
		t.Fatalf("frame reorder must report ErrCorruptFrame, got %v", erErr(dr))
	}
}

// TestCrossFileSpliceDetected takes a frame from one recording and splices it
// into another encrypted with the SAME key; the differing per-file stream id
// must make it fail authentication (V2 anti-splice property).
func TestCrossFileSpliceDetected(t *testing.T) {
	key, _ := GenerateKey() // same key for both files
	mk := func(payload string) []byte {
		var b bytes.Buffer
		w, _ := NewWriter(&b, key)
		_, _ = w.Write([]byte(payload))
		_, _ = w.Write([]byte("filler frame\n"))
		return b.Bytes()
	}
	a := mk("file A secret\n")
	b := mk("file B secret\n")
	ao := frameOffsets(t, a)
	bo := frameOffsets(t, b)

	// Replace A's frame 0 with B's frame 0 (same index, same key, different
	// stream id baked into B's frame AAD).
	bFrame0 := b[bo[0]:bo[1]]
	spliced := append([]byte{}, a[:ao[0]]...) // A header (A's stream id)
	spliced = append(spliced, bFrame0...)     // B's frame 0
	spliced = append(spliced, a[ao[1]:]...)   // A's remaining frames

	dr := openV2(t, spliced, key)
	got, _ := io.ReadAll(dr)
	if strings.Contains(string(got), "file B secret") {
		t.Fatal("a frame spliced from another file must not authenticate")
	}
	if er, ok := dr.(Errer); !ok || !errors.Is(er.Err(), ErrCorruptFrame) {
		t.Fatalf("cross-file splice must report ErrCorruptFrame, got %v", erErr(dr))
	}
}

// TestNonceUniqueness extracts the 12-byte nonce from many framed writes and
// asserts there are no duplicates.
func TestNonceUniqueness(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	const n = 2000
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte("payload\n")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	out := buf.Bytes()
	offs := frameOffsets(t, out)
	if len(offs) != n {
		t.Fatalf("expected %d frames, got %d", n, len(offs))
	}
	const nonceSize = 12 // AES-GCM standard nonce
	seen := make(map[string]struct{}, n)
	for _, off := range offs {
		nonce := out[off+4 : off+4+nonceSize]
		k := string(nonce)
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate nonce at frame offset %d: %x", off, nonce)
		}
		seen[k] = struct{}{}
	}
}

// TestOversizedLengthPrefix forges a length prefix above maxFrameSize and
// asserts the reader rejects it rather than attempting a huge allocation/read.
func TestOversizedLengthPrefix(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	_, _ = w.Write([]byte("a real first frame\n"))

	out := buf.Bytes()
	// Append a bogus oversized frame: length prefix > maxFrameSize, no payload.
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], maxFrameSize+1)
	forged := append(append([]byte{}, out...), lenbuf[:]...)

	dr := openV2(t, forged, key)

	// First read yields the legitimate frame.
	first := make([]byte, 64)
	nr, err := dr.Read(first)
	if err != nil {
		t.Fatalf("first frame read: %v", err)
	}
	if !strings.Contains(string(first[:nr]), "a real first frame") {
		t.Fatalf("unexpected first frame: %q", first[:nr])
	}
	// Next read hits the oversized prefix and must error distinctly (not EOF).
	_, err = dr.Read(first)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("oversized length prefix should yield io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestEmptyWriteIsNoOp asserts an empty Write emits no frame and reports 0, nil.
func TestEmptyWriteIsNoOp(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	header := len(MagicV2) + streamIDSize
	if buf.Len() != header {
		t.Fatalf("expected only magic + stream id written (%d bytes), got %d", header, buf.Len())
	}

	n, err := w.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("empty Write: got (%d, %v), want (0, nil)", n, err)
	}
	n, err = w.Write([]byte{})
	if n != 0 || err != nil {
		t.Fatalf("zero-length Write: got (%d, %v), want (0, nil)", n, err)
	}
	if buf.Len() != header {
		t.Fatalf("empty Write emitted bytes: buffer grew from %d to %d", header, buf.Len())
	}
}

// TestWrongKeySizeRejected asserts both the writer and reader constructors
// reject a key that is not exactly KeySize bytes, with a clear error and no
// panic (a short/long key must never reach aes.NewCipher and corrupt state).
func TestWrongKeySizeRejected(t *testing.T) {
	var buf bytes.Buffer
	for _, n := range []int{0, 1, KeySize - 1, KeySize + 1, 64} {
		key := make([]byte, n)
		if _, err := NewWriter(&buf, key); err == nil {
			t.Errorf("NewWriter accepted %d-byte key, want error", n)
		}
		if _, err := NewReaderV2(bytes.NewReader(nil), key); err == nil {
			t.Errorf("NewReaderV2 accepted %d-byte key, want error", n)
		}
		if _, err := NewReader(bytes.NewReader(nil), key); err == nil {
			t.Errorf("NewReader accepted %d-byte key, want error", n)
		}
	}
}

// TestMagicVersionDetection covers the prefix classifier for V2, V1, plaintext,
// and a too-short prefix (must not panic or over-read).
func TestMagicVersionDetection(t *testing.T) {
	if got := MagicVersion([]byte(MagicV2)); got != 2 {
		t.Errorf("MagicVersion(V2) = %d, want 2", got)
	}
	if got := MagicVersion([]byte(Magic)); got != 1 {
		t.Errorf("MagicVersion(V1) = %d, want 1", got)
	}
	if got := MagicVersion([]byte("plain text not magic")); got != 0 {
		t.Errorf("MagicVersion(plaintext) = %d, want 0", got)
	}
	if got := MagicVersion([]byte("TT")); got != 0 {
		t.Errorf("MagicVersion(short prefix) = %d, want 0 (no over-read/panic)", got)
	}
	if got := MagicVersion(nil); got != 0 {
		t.Errorf("MagicVersion(nil) = %d, want 0", got)
	}
}

// TestTruncatedStreamIDIsCleanEOF truncates a V2 stream inside the 16-byte stream
// id (before any frame). The reader must treat it as a clean EOF — no plaintext,
// no error — exactly like a daemon that died before writing the first frame.
func TestTruncatedStreamIDIsCleanEOF(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	_, _ = w.Write([]byte("never fully written\n"))

	// Keep the magic and only part of the stream id.
	out := buf.Bytes()
	truncated := out[:len(MagicV2)+streamIDSize-3]

	dr := openV2(t, truncated, key)
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("truncated stream id should be clean EOF, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("no plaintext expected, got %q", got)
	}
	if er, ok := dr.(Errer); !ok || er.Err() != nil {
		t.Fatalf("truncation in stream id must not report corruption, got %v", erErr(dr))
	}
}

// TestOversizedWriteRejected asserts the writer refuses a plaintext Write whose
// resulting frame would exceed maxFrameSize, rather than wrapping the uint32
// length prefix.
func TestOversizedWriteRejected(t *testing.T) {
	key, _ := GenerateKey()
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	header := len(MagicV2) + streamIDSize
	// Plaintext at maxFrameSize already overflows once nonce+tag are added.
	big := make([]byte, maxFrameSize)
	n, err := w.Write(big)
	if err == nil {
		t.Fatal("expected error for oversized Write, got nil")
	}
	if n != 0 {
		t.Fatalf("oversized Write should report 0 bytes, got %d", n)
	}
	if buf.Len() != header {
		t.Fatalf("oversized Write must not emit a frame: buffer is %d bytes", buf.Len())
	}
}
