package nethernet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var wakeWho = Identity{XUID: "2535400000000001", Gamertag: "Synthetic Steve"}

func TestAPIWakerSendsTheTokenPortAndPlayer(t *testing.T) {
	var gotPath, gotToken, gotCT, gotInternalKey string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-NetherNet-Router-Token")
		gotInternalKey = r.Header.Get("X-Internal-API-Key")
		gotCT = r.Header.Get("Content-Type")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_, _ = w.Write([]byte(`{"success":true,"woken":true,"booting":false,"message":"waking"}`))
	}))
	defer srv.Close()

	res, err := NewAPIWaker(srv.URL+"/", "router-secret", srv.Client()).Wake(context.Background(), 30017, wakeWho)
	require.NoError(t, err)
	assert.Equal(t, WakeResult{Woken: true, Message: "waking"}, res)
	assert.Equal(t, "/v1/internal/servers/bedrock/nethernet-wake", gotPath)
	assert.Equal(t, "router-secret", gotToken)
	assert.Empty(t, gotInternalKey, "the master internal key is never sent")
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, map[string]any{"port": float64(30017), "xuid": "2535400000000001", "gamertag": "Synthetic Steve"}, gotBody)
}

func TestAPIWakerDecodesBooting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"woken":false,"booting":true,"message":"already starting"}`))
	}))
	defer srv.Close()

	res, err := NewAPIWaker(srv.URL, "t", srv.Client()).Wake(context.Background(), 1, wakeWho)
	require.NoError(t, err)
	assert.Equal(t, WakeResult{Booting: true, Message: "already starting"}, res)
}

func TestAPIWakerErrorsOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"message":"bad token"}`))
	}))
	defer srv.Close()

	_, err := NewAPIWaker(srv.URL, "wrong", srv.Client()).Wake(context.Background(), 1, wakeWho)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestAPIWakerErrorsWhenSuccessIsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"woken":true,"booting":false,"message":"no"}`))
	}))
	defer srv.Close()

	_, err := NewAPIWaker(srv.URL, "t", srv.Client()).Wake(context.Background(), 1, wakeWho)
	assert.Error(t, err)
}

func TestAPIWakerHonoursTheContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release) // runs before srv.Close, which waits for the handler

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := NewAPIWaker(srv.URL, "t", srv.Client()).Wake(ctx, 1, wakeWho)
	assert.Error(t, err)
}

func TestReadyFalseOnRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().(*net.TCPAddr).AddrPort()
	require.NoError(t, l.Close())

	assert.False(t, Ready(context.Background(), addr, time.Second))
}

func TestReadyTrueOnListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	assert.True(t, Ready(context.Background(), l.Addr().(*net.TCPAddr).AddrPort(), time.Second))
}

func TestReadyFalseOnAnInvalidAddress(t *testing.T) {
	assert.False(t, Ready(context.Background(), netip.AddrPort{}, time.Second))
}
