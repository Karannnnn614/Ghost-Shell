// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package ollama is a minimal client for a local Ollama server, used by
// `ghostshell analyze` to run a fully offline model pass over a session's
// deterministic analysis Summary.
//
// The whole point of this feature is that session data — which can contain
// secrets — never leaves the machine. So the client refuses, before making any
// network call, to talk to a non-loopback host unless the operator explicitly
// passes AllowRemote. It is also entirely optional: when the Ollama server is
// not running, Generate returns an error wrapping ErrUnavailable so the caller
// can print a friendly "install Ollama" hint and still show the deterministic
// report. It is never a hard dependency of core recording or replay.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the loopback endpoint a stock Ollama install listens on.
const DefaultBaseURL = "http://localhost:11434"

// DefaultModel is the local model used when --model is not given. It is only a
// default label — the operator is expected to have pulled it (`ollama pull`).
const DefaultModel = "llama3.1"

// ErrUnavailable indicates the Ollama server could not be reached (not
// installed, not running, or a stale endpoint). Callers use errors.Is to
// distinguish "Ollama isn't there" (print an install hint, keep going) from a
// real server-side error (surface it).
var ErrUnavailable = errors.New("ollama server not reachable")

// Client talks to one Ollama endpoint with one model.
type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

// New validates the endpoint and returns a Client. baseURL may be empty (uses
// DefaultBaseURL) or a bare host:port (http:// is assumed). model may be empty
// (uses DefaultModel).
//
// Crucially, when allowRemote is false, New returns an error WITHOUT making any
// network call if baseURL's host is not loopback — the guard runs before a
// single byte of session data could be sent anywhere. Pass allowRemote only
// when the operator has explicitly opted in via --allow-remote.
func New(baseURL, model string, allowRemote bool) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	if strings.TrimSpace(model) == "" {
		model = DefaultModel
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ollama endpoint %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ollama endpoint must be http/https, got %q", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("ollama endpoint %q has no host", baseURL)
	}
	if !allowRemote && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf(
			"refusing to send session data to non-loopback Ollama host %q — session recordings can contain secrets; pass --allow-remote to override",
			u.Hostname())
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		http:    &http.Client{Timeout: 3 * time.Minute},
	}, nil
}

// Model returns the model this client will ask Ollama to run.
func (c *Client) Model() string { return c.model }

// isLoopbackHost reports whether host names the local machine's loopback
// interface: the literal "localhost", or any IP (v4 or v6) that IsLoopback.
// Any other hostname is treated as non-loopback (we do not resolve it — a name
// that happens to resolve to 127.0.0.1 is still refused without --allow-remote,
// which is the safe default).
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// generateRequest is the /api/generate request body (stream disabled — one
// response object).
type generateRequest struct {
	Model  string `json:"model"`
	System string `json:"system,omitempty"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// generateResponse is the (non-streamed) /api/generate response; we only need
// the generated text.
type generateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Generate runs one non-streaming completion against /api/generate and returns
// the model's text. A connection failure (server not running) is returned as an
// error wrapping ErrUnavailable; a reachable-but-erroring server (bad model,
// HTTP 5xx) returns a descriptive non-ErrUnavailable error. The supplied
// context bounds the call.
func (c *Client) Generate(ctx context.Context, system, prompt string) (string, error) {
	body, err := json.Marshal(generateRequest{
		Model:  c.model,
		System: system,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", fmt.Errorf("encoding ollama request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// A timeout is reported as-is; any other transport failure (connection
		// refused, no route, DNS) means the server isn't there → ErrUnavailable.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "", fmt.Errorf("ollama request timed out: %w", err)
		}
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		snippet := readSnippet(resp.Body)
		return "", fmt.Errorf("ollama returned 404 — is the model %q pulled? run `ollama pull %s`%s", c.model, c.model, snippet)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama HTTP %d%s", resp.StatusCode, readSnippet(resp.Body))
	}

	var gr generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", fmt.Errorf("decoding ollama response: %w", err)
	}
	return strings.TrimSpace(gr.Response), nil
}

// readSnippet returns a short, printable suffix of an error response body (": <text>")
// or "" if the body is empty/unreadable. Bounded so a large body can't flood output.
func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	return ": " + s
}
