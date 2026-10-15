package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/extras/v2/realm"
)

func useNopLogger(t *testing.T) {
	t.Helper()
	previous := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = previous })
}

func newTestRealmRuntime(t *testing.T, handler http.HandlerFunc) *realmServerRuntime {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	client, err := realm.NewClient(realm.ClientConfig{BaseURL: u, Token: "token"})
	require.NoError(t, err)
	return &realmServerRuntime{
		client:  client,
		realmID: "realm",
		addrs:   []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:4433")},
	}
}

func writeRealmError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(realm.ErrorResponse{Error: code})
}

func TestRealmRegisterAtStartupWaitsForStaleSession(t *testing.T) {
	useNopLogger(t)
	var mu sync.Mutex
	attempts := 0
	rt := newTestRealmRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			// The name is still held by the session of a run that crashed.
			writeRealmError(w, http.StatusConflict, "realm_taken")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(realm.RegisterResponse{SessionID: "session", TTL: 60})
	})

	sess, err := rt.registerAtStartup(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "session", sess.id)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, attempts)
}

func TestRealmRegisterAtStartupStopsOnConfigErrors(t *testing.T) {
	useNopLogger(t)
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var mu sync.Mutex
			attempts := 0
			rt := newTestRealmRuntime(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				attempts++
				mu.Unlock()
				writeRealmError(w, status, "error")
			})
			_, err := rt.registerAtStartup(context.Background())
			require.Error(t, err)
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, 1, attempts)
		})
	}
}

// A failed heartbeat is retried quickly, and addresses it carried are sent
// again: they never reached the server.
func TestRealmHeartbeatRetriesAndResendsAddresses(t *testing.T) {
	useNopLogger(t)
	newAddrs := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:4433")}
	type heartbeat struct {
		at        time.Time
		addresses []string
	}
	var mu sync.Mutex
	var seen []heartbeat
	done := make(chan struct{})
	var rt *realmServerRuntime
	rt = newTestRealmRuntime(t, func(w http.ResponseWriter, r *http.Request) {
		var req realm.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, heartbeat{at: time.Now(), addresses: req.Addresses})
		n := len(seen)
		mu.Unlock()
		switch n {
		case 1:
			// The addresses change after the loop has taken its
			// snapshot, so the next heartbeat carries them.
			rt.mu.Lock()
			rt.addrs = newAddrs
			rt.mu.Unlock()
			writeRealmError(w, http.StatusServiceUnavailable, "unavailable")
		case 2:
			writeRealmError(w, http.StatusServiceUnavailable, "unavailable")
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(realm.HeartbeatResponse{TTL: 60})
			if n == 3 {
				close(done)
			}
		}
	})
	rt.config.HeartbeatInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan error, 1)
	go func() { loopDone <- rt.heartbeatLoop(ctx, realmSession{id: "session", ttl: 60}) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat was not retried")
	}
	cancel()
	<-loopDone

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(seen), 3)
	assert.Nil(t, seen[0].addresses)
	assert.Equal(t, []string{"203.0.113.20:4433"}, seen[1].addresses)
	assert.Equal(t, []string{"203.0.113.20:4433"}, seen[2].addresses, "addresses from the failed heartbeat must be sent again")
	assert.Less(t, seen[2].at.Sub(seen[1].at), time.Second)
}

func TestRealmHeartbeatTiming(t *testing.T) {
	rt := &realmServerRuntime{}
	assert.Equal(t, 20*time.Second, rt.heartbeatInterval(60))
	assert.Equal(t, 20*time.Second, rt.heartbeatInterval(0))
	rt.config.HeartbeatInterval = 5 * time.Second
	assert.Equal(t, 5*time.Second, rt.heartbeatInterval(60))
	rt.config.HeartbeatInterval = -time.Second
	assert.Equal(t, 20*time.Second, rt.heartbeatInterval(60))

	assert.Equal(t, 2*time.Second, realmHeartbeatRetryDelay(1, 20*time.Second))
	assert.Equal(t, 4*time.Second, realmHeartbeatRetryDelay(2, 20*time.Second))
	assert.Equal(t, 8*time.Second, realmHeartbeatRetryDelay(3, 20*time.Second))
	assert.Equal(t, 20*time.Second, realmHeartbeatRetryDelay(10, 20*time.Second))
	assert.Equal(t, time.Second, realmHeartbeatRetryDelay(1, time.Second))
}

func TestRealmEventStreamWatchdog(t *testing.T) {
	useNopLogger(t)
	open := func(t *testing.T, sendAck bool) *realm.EventStream {
		rt := newTestRealmRuntime(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			if sendAck {
				_, _ = fmt.Fprint(w, "event: heartbeat_ack\ndata: {\"ttl\":60}\n\n")
			}
			w.(http.Flusher).Flush()
			// Then go quiet, like a connection that died silently.
			<-r.Context().Done()
		})
		stream, err := rt.client.Events(context.Background(), "realm", "session")
		require.NoError(t, err)
		t.Cleanup(func() { _ = stream.Close() })
		return stream
	}
	next := func(stream *realm.EventStream) <-chan error {
		ch := make(chan error, 1)
		go func() {
			_, err := stream.Next()
			ch <- err
		}()
		return ch
	}
	rt := &realmServerRuntime{realmID: "realm"}

	t.Run("closes a stream whose acks stopped", func(t *testing.T) {
		stream := open(t, true)
		nextErr := next(stream)
		stop := rt.watchEventStream(context.Background(), stream, 100*time.Millisecond)
		defer stop()
		select {
		case err := <-nextErr:
			assert.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("stalled stream was not closed")
		}
	})
	t.Run("leaves servers without acks alone", func(t *testing.T) {
		stream := open(t, false)
		nextErr := next(stream)
		stop := rt.watchEventStream(context.Background(), stream, 50*time.Millisecond)
		defer stop()
		select {
		case err := <-nextErr:
			t.Fatalf("stream was closed: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
	})
}
