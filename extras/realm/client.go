package realm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxErrorBodySize = 64 * 1024

const (
	// responseHeaderTimeout bounds how long a request waits for response
	// headers. The server holds connect requests for up to about 10
	// seconds, so this has to stay well above that.
	responseHeaderTimeout = 30 * time.Second
	// http2PingTimeout is how long an HTTP/2 connection may stay silent
	// before it is pinged, and how long the ping may go unanswered before
	// the connection is closed.
	http2PingTimeout = 15 * time.Second
)

// NewHTTPTransport returns an HTTP transport for talking to a rendezvous
// server. Unlike http.DefaultTransport, it notices dead HTTP/2 connections,
// which would otherwise stall the event stream and every request sharing
// the connection until the OS gives up on it, and it bounds how long a
// request waits for response headers.
func NewHTTPTransport() *http.Transport {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
	}
	tr.ResponseHeaderTimeout = responseHeaderTimeout
	tr.HTTP2 = &http.HTTP2Config{
		SendPingTimeout: http2PingTimeout,
		PingTimeout:     http2PingTimeout,
	}
	return tr
}

var defaultHTTPClient = sync.OnceValue(func() *http.Client {
	return &http.Client{Transport: NewHTTPTransport()}
})

const (
	PunchNonceSize   = 16
	PunchObfsKeySize = 32
)

var ErrInvalidClientConfig = errors.New("invalid realm client config")

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type ClientConfig struct {
	BaseURL    *url.URL
	Token      string
	HTTPClient *http.Client
}

type RegisterResponse struct {
	SessionID string `json:"session_id"`
	TTL       int    `json:"ttl"`
}

type HeartbeatResponse struct {
	TTL int `json:"ttl"`
}

type HeartbeatRequest struct {
	Addresses []string `json:"addresses,omitempty"`
}

type PunchMetadata struct {
	Nonce string `json:"nonce"`
	Obfs  string `json:"obfs"`
}

type ConnectRequest struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type ConnectResponse struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type PunchEvent struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type StatusError struct {
	StatusCode int
	Response   ErrorResponse
}

func (e *StatusError) Error() string {
	if e.Response.Error != "" || e.Response.Message != "" {
		return fmt.Sprintf("realm server returned %d: %s: %s", e.StatusCode, e.Response.Error, e.Response.Message)
	}
	return fmt.Sprintf("realm server returned %d", e.StatusCode)
}

func NewClientFromAddr(addr *Addr, httpClient *http.Client) (*Client, error) {
	if addr == nil {
		return nil, fmt.Errorf("%w: addr is nil", ErrInvalidClientConfig)
	}
	return NewClient(ClientConfig{
		BaseURL:    addr.BaseURL(),
		Token:      addr.Token,
		HTTPClient: httpClient,
	})
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.BaseURL == nil {
		return nil, fmt.Errorf("%w: base URL is nil", ErrInvalidClientConfig)
	}
	if config.BaseURL.Scheme != "https" && config.BaseURL.Scheme != "http" {
		return nil, fmt.Errorf("%w: base URL scheme must be http or https", ErrInvalidClientConfig)
	}
	if config.BaseURL.Host == "" {
		return nil, fmt.Errorf("%w: base URL host is required", ErrInvalidClientConfig)
	}
	if config.Token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidClientConfig)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	baseURL := *config.BaseURL
	baseURL.RawQuery = ""
	baseURL.Fragment = ""
	return &Client{
		baseURL:    &baseURL,
		token:      config.Token,
		httpClient: httpClient,
	}, nil
}

func NewPunchMetadata() (PunchMetadata, error) {
	nonce, err := randHex(PunchNonceSize)
	if err != nil {
		return PunchMetadata{}, err
	}
	obfs, err := randHex(PunchObfsKeySize)
	if err != nil {
		return PunchMetadata{}, err
	}
	return PunchMetadata{
		Nonce: nonce,
		Obfs:  obfs,
	}, nil
}

func (c *Client) Register(ctx context.Context, realmID string, addresses []string) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "", c.token, addressRequest{Addresses: addresses}, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Deregister(ctx context.Context, realmID, sessionID string) error {
	return c.doJSON(ctx, http.MethodDelete, realmID, "", sessionID, nil, http.StatusNoContent, nil)
}

func (c *Client) Heartbeat(ctx context.Context, realmID, sessionID string, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "heartbeat", sessionID, req, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Connect(ctx context.Context, realmID string, req ConnectRequest) (*ConnectResponse, error) {
	var resp ConnectResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "connect", c.token, req, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type ConnectResponseRequest struct {
	Addresses []string `json:"addresses"`
}

func (c *Client) ConnectResponse(ctx context.Context, realmID, sessionID, nonce string, addresses []string) error {
	subPath := "connects/" + url.PathEscape(nonce)
	return c.doJSON(ctx, http.MethodPost, realmID, subPath, sessionID,
		ConnectResponseRequest{Addresses: addresses}, http.StatusNoContent, nil)
}

func (c *Client) Events(ctx context.Context, realmID, sessionID string) (*EventStream, error) {
	req, err := c.newRequest(ctx, http.MethodGet, realmID, "events", sessionID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, decodeStatusError(resp)
	}
	return newEventStream(resp), nil
}

type addressRequest struct {
	Addresses []string `json:"addresses"`
}

func (c *Client) doJSON(ctx context.Context, method, realmID, subPath, token string, in any, expectedStatus int, out any) error {
	var body io.Reader
	if in != nil {
		bs, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(bs)
	}
	req, err := c.newRequest(ctx, method, realmID, subPath, token, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectedStatus {
		return decodeStatusError(resp)
	}
	if out == nil || resp.Body == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) newRequest(ctx context.Context, method, realmID, subPath, token string, body io.Reader) (*http.Request, error) {
	if realmID == "" || strings.Contains(realmID, "/") {
		return nil, fmt.Errorf("%w: realm id must be a single path segment", ErrInvalidAddr)
	}
	u := *c.baseURL
	u.Path = joinURLPath(c.baseURL.Path, "v1", url.PathEscape(realmID), subPath)
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func randHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func joinURLPath(parts ...string) string {
	var joined []string
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part == "" {
			continue
		}
		joined = append(joined, part)
	}
	return "/" + strings.Join(joined, "/")
}

func decodeStatusError(resp *http.Response) error {
	var errResp ErrorResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodySize)).Decode(&errResp)
	return &StatusError{
		StatusCode: resp.StatusCode,
		Response:   errResp,
	}
}

type EventStream struct {
	resp    *http.Response
	scanner *bufio.Scanner

	mu      sync.Mutex
	lastAck time.Time
}

func newEventStream(resp *http.Response) *EventStream {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	return &EventStream{
		resp:    resp,
		scanner: scanner,
	}
}

func (s *EventStream) Close() error {
	return s.resp.Body.Close()
}

// LastHeartbeatAck returns when the stream last delivered a heartbeat_ack
// event, or the zero time if it hasn't delivered one. The server sends one
// after every successful heartbeat, so a stream that stops delivering them
// is probably dead even if its connection still looks open. It is safe to
// call while another goroutine is blocked in Next.
func (s *EventStream) LastHeartbeatAck() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAck
}

// Next returns the next punch event. Other events are consumed without
// being returned; heartbeat_ack events update LastHeartbeatAck.
func (s *EventStream) Next() (*PunchEvent, error) {
	var eventName string
	var data strings.Builder
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			if eventName == "" && data.Len() == 0 {
				continue
			}
			if eventName == "heartbeat_ack" {
				s.mu.Lock()
				s.lastAck = time.Now()
				s.mu.Unlock()
			}
			if eventName != "punch" {
				eventName = ""
				data.Reset()
				continue
			}
			var ev PunchEvent
			if err := json.Unmarshal([]byte(data.String()), &ev); err != nil {
				return nil, err
			}
			return &ev, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			eventName = value
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}
	if err := s.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}
