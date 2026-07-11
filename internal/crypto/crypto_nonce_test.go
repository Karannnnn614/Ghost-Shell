// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// nonceSizeV2 is the AES-256-GCM standard nonce length (12 bytes / 96 bits).
const nonceSizeV2 = 12

// framesNonces returns the per-frame nonces of an encrypted stream in order.
func framesNonces(t *testing.T, b []byte) [][]byte {
	t.Helper()
	offs := frameOffsets(t, b)
	nonces := make([][]byte, 0, len(offs))
	for _, off := range offs {
		nonces = append(nonces, b[off+4:off+4+nonceSizeV2])
	}
	return nonces
}

// TestNonceIndependentOfCounterAndPayload proves the per-frame nonce is fresh
// crypto/rand data, NOT derived from the frame counter or the plaintext:
//
//	(a) two independent streams writing byte-identical payloads at identical
//	    positions produce different nonces at every position. A counter-derived
//	    nonce (nonce == f(index)) would make them collide; a payload-derived
//	    nonce would too. They don't, so the nonce depends on neither.
//	(b) no frame's nonce equals its frame index encoded as a 12-byte value, i.e.
//	    the counter is never reused as (or leaked into) the nonce.
//
// Together with the existing reorder/splice tests (which prove the counter IS
// bound into the AAD), this confirms the counter is used ONLY for AAD and the
// nonce is independent of it — so there is no cross-restart nonce reuse under a
// fixed key beyond the random-96-bit birthday bound.
func TestNonceIndependentOfCounterAndPayload(t *testing.T) {
	key, _ := GenerateKey()
	const n = 512
	payload := []byte("identical payload across both streams\n")

	mk := func() [][]byte {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, key)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if _, err := w.Write(payload); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		return framesNonces(t, buf.Bytes())
	}

	a, b := mk(), mk()
	if len(a) != n || len(b) != n {
		t.Fatalf("frame count mismatch: a=%d b=%d want %d", len(a), len(b), n)
	}
	for i := 0; i < n; i++ {
		if bytes.Equal(a[i], b[i]) {
			t.Fatalf("frame %d: identical nonce across independent streams %x — nonce is derived from counter/payload, not random", i, a[i])
		}
	}

	// (b) nonce is never the frame index encoded as a nonce.
	counterAsNonce := make([]byte, nonceSizeV2)
	for i := 0; i < n; i++ {
		for j := range counterAsNonce {
			counterAsNonce[j] = 0
		}
		binary.BigEndian.PutUint64(counterAsNonce[nonceSizeV2-8:], uint64(i))
		if bytes.Equal(a[i], counterAsNonce) {
			t.Fatalf("frame %d nonce equals the counter encoded as a nonce %x — counter leaked into nonce", i, a[i])
		}
	}
}

// TestNoncesUniqueAcrossManyFrames strengthens the birthday-bound argument
// empirically: across a large number of frames under a single key, every 96-bit
// nonce is distinct (a counter or a buggy PRNG would collide). The theoretical
// bound: with random 96-bit nonces, the ~50% collision point is ~2^48 frames
// (birthday bound sqrt(2^96)); at, say, 10^9 frames the collision probability is
// ~10^9^2 / 2^97 ~= 2^60 / 2^97 = 2^-37 (~7e-12) — negligible for any realistic
// recording volume.
func TestNoncesUniqueAcrossManyFrames(t *testing.T) {
	key, _ := GenerateKey()
	const n = 20000
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, key)
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte("f\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	seen := make(map[string]int, n)
	for i, nonce := range framesNonces(t, buf.Bytes()) {
		if prev, dup := seen[string(nonce)]; dup {
			t.Fatalf("duplicate nonce %x at frames %d and %d", nonce, prev, i)
		}
		seen[string(nonce)] = i
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique nonces, got %d", n, len(seen))
	}
}
