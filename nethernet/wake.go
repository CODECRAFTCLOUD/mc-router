package nethernet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Identity is a player whose Minecraft identity token verified (identity.go).
// XUID keys the signal server's per-player wake limit (R34) and goes to the
// wake API with Gamertag, which the API records on the wake event.
type Identity struct {
	XUID, Gamertag string
}

// WakeResult is the API's answer: Booting means the server is already
// starting or running, so the router only has to wait for it.
type WakeResult struct {
	Woken, Booting bool
	Message        string
}

type Waker interface {
	Wake(ctx context.Context, legacyPort int, who Identity) (WakeResult, error)
}

const nethernetWakePath = "/v1/internal/servers/bedrock/nethernet-wake"

type apiWaker struct {
	url, token string
	hc         *http.Client
}

// NewAPIWaker calls the uniz.host API's NetherNet wake endpoint with the
// router's own token (never the master internal key).
func NewAPIWaker(apiURL, token string, hc *http.Client) Waker {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &apiWaker{url: strings.TrimSuffix(apiURL, "/") + nethernetWakePath, token: token, hc: hc}
}

func (w *apiWaker) Wake(ctx context.Context, legacyPort int, who Identity) (WakeResult, error) {
	body, err := json.Marshal(struct {
		Port     int    `json:"port"`
		XUID     string `json:"xuid"`
		Gamertag string `json:"gamertag"`
	}{legacyPort, who.XUID, who.Gamertag})
	if err != nil {
		return WakeResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return WakeResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NetherNet-Router-Token", w.token)
	resp, err := w.hc.Do(req)
	if err != nil {
		return WakeResult{}, fmt.Errorf("nethernet wake: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return WakeResult{}, fmt.Errorf("nethernet wake: API returned %d", resp.StatusCode)
	}
	var out struct {
		Success, Woken, Booting bool
		Message                 string
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return WakeResult{}, fmt.Errorf("nethernet wake: decode: %w", err)
	}
	if !out.Success {
		return WakeResult{}, fmt.Errorf("nethernet wake: API refused: %s", out.Message)
	}
	return WakeResult{Woken: out.Woken, Booting: out.Booting, Message: out.Message}, nil
}

// Ready reports whether a TCP dial to addr succeeds within timeout.
func Ready(ctx context.Context, addr netip.AddrPort, timeout time.Duration) bool {
	if !addr.IsValid() {
		return false
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
