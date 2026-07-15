// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewRejectsNonLoopbackWithoutAllow is the core safety-rail test: a
// non-loopback endpoint with allowRemote=false must be refused at construction,
// before any network call, so session data can never be sent off-box by default.
func TestNewRejectsNonLoopbackWithoutAllow(t *testing.T) {
	for _, host := range []string{
		"http://10.0.0.5:11434",
		"http://192.168.1.20:11434",
		"http://ollama.example.com:11434",
		"http://8.8.8.8:11434",
	} {
		if _, err := New(host, "m", false); err == nil {
			t.Errorf("New(%q, allowRemote=false) = nil error, want refusal", host)
		}
	}
}

// TestNewAllowsLoopback: the loopback forms are accepted without --allow-remote.
func TestNewAllowsLoopback(t *testing.T) {
	for _, host := range []string{
		"", // default (localhost)
		"http://localhost:11434",
		"http://127.0.0.1:11434",
		"http://127.0.0.5:99",
		"http://[::1]:11434",
	} {
		if _, err := New(host, "m", false); err != nil {
			t.Errorf("New(%q, allowRemote=false) = %v, want ok (loopback)", host, err)
		}
	}
}

// TestNewAllowsNonLoopbackWithAllow: --allow-remote opts in to a remote host.
func TestNewAllowsNonLoopbackWithAllow(t *testing.T) {
	if _, err := New("http://10.0.0.5:11434", "m", true); err != nil {
		t.Errorf("New(remote, allowRemote=true) = %v, want ok", err)
	}
}

// TestNewRejectsBadScheme: only http/https endpoints are accepted.
func TestNewRejectsBadScheme(t *testing.T) {
	for _, host := range []string{"ftp://localhost:11434", "localhost:11434 with spaces"} {
		if _, err := New(host, "m", false); err == nil {
			t.Errorf("New(%q) = nil error, want rejection", host)
		}
	}
}

// TestGenerateHappyPath: against a loopback stub (httptest listens on 127.0.0.1),
// Generate posts model+prompt+system to /api/generate and returns the text.
func TestGenerateHappyPath(t *testing.T) {
	var gotBody generateRequest
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_ = json.NewEncoder(w).Encode(generateResponse{Response: "  looks clean.  ", Done: true})
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:PORT — loopback, so no --allow-remote needed.
	c, err := New(srv.URL, "mymodel", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Generate(context.Background(), "sys", "user prompt with SUMMARY")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != "looks clean." {
		t.Errorf("Generate returned %q, want trimmed %q", out, "looks clean.")
	}
	if gotPath != "/api/generate" {
		t.Errorf("posted to %q, want /api/generate", gotPath)
	}
	if gotBody.Model != "mymodel" {
		t.Errorf("request model = %q, want mymodel", gotBody.Model)
	}
	if gotBody.System != "sys" || !strings.Contains(gotBody.Prompt, "SUMMARY") {
		t.Errorf("request did not carry system/prompt: %+v", gotBody)
	}
	if gotBody.Stream {
		t.Errorf("request should set stream=false")
	}
}

// TestGenerateUnavailable: when nothing is listening, Generate returns an error
// wrapping ErrUnavailable so the CLI can print an install hint and keep going.
func TestGenerateUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // free the port; connections now refused

	c, err := New(url, "m", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, gerr := c.Generate(context.Background(), "", "p")
	if !errors.Is(gerr, ErrUnavailable) {
		t.Errorf("Generate against closed server = %v, want ErrUnavailable", gerr)
	}
}

// TestGenerateServerError: a reachable server returning 5xx is a real error, NOT
// ErrUnavailable (Ollama is running but something is wrong — surface it).
func TestGenerateServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "m", false)
	_, gerr := c.Generate(context.Background(), "", "p")
	if gerr == nil {
		t.Fatal("Generate against 500 = nil, want error")
	}
	if errors.Is(gerr, ErrUnavailable) {
		t.Errorf("500 should not be ErrUnavailable: %v", gerr)
	}
	if !strings.Contains(gerr.Error(), "500") {
		t.Errorf("error should mention the status: %v", gerr)
	}
}
