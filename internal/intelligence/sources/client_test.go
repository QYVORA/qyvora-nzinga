package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoAppliesUserAgentAndCap(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		w.Write([]byte(strings.Repeat("x", 1024)))
	}))
	defer srv.Close()

	c, err := NewClient(ClientOptions{UserAgent: "nzinga-test/1.0", MaxResponseBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Do(context.Background(), "GET", srv.URL+"/a", nil)
	if err == nil {
		t.Fatal("expected a cap error for an oversized body")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected cap error, got %v", err)
	}
	if gotUA != "nzinga-test/1.0" {
		t.Fatalf("user agent not applied: %q", gotUA)
	}
}

func TestDoWithinCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, _ := NewClient(ClientOptions{MaxResponseBytes: 1024})
	resp, body, err := c.Do(context.Background(), "GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if string(body) != "ok" || resp.StatusCode != 200 {
		t.Fatalf("unexpected body/status: %q %d", body, resp.StatusCode)
	}
}

func TestRedirectsRefusedCrossOrigin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("cross-origin redirect must never be followed")
	}))
	defer target.Close()
	// Redirect to a different host (port differs -> different origin).
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	c, _ := NewClient(ClientOptions{FollowRedirects: true, MaxResponseBytes: 1024})
	_, _, err := c.Do(context.Background(), "GET", redirector.URL, nil)
	if err == nil {
		t.Fatal("cross-origin redirect must be refused")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected SSRF guard error, got %v", err)
	}
}

func TestRedirectsNotFollowedByDefault(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("default client must not follow redirects")
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	c, _ := NewClient(ClientOptions{})
	resp, _, err := c.Do(context.Background(), "GET", redirector.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected the raw 302 when redirects are disabled, got %d", resp.StatusCode)
	}
}

func TestSameOriginRedirectFollowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("arrived"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := NewClient(ClientOptions{FollowRedirects: true, MaxResponseBytes: 1024})
	resp, body, err := c.Do(context.Background(), "GET", srv.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(body) != "arrived" {
		t.Fatalf("same-origin redirect not followed: %d %q", resp.StatusCode, body)
	}
}

func TestRetryRecoversFromServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	c, _ := NewClient(ClientOptions{MaxRetries: 2})
	_, body, err := c.Do(context.Background(), "GET", srv.URL, nil)
	if err != nil {
		t.Fatalf("retry should recover: %v", err)
	}
	if string(body) != "recovered" {
		t.Fatalf("expected recovered body, got %q", body)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected at least one retry, got %d calls", calls.Load())
	}
}

func TestStopRetryingOnSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
		calls.Add(1)
	}))
	defer srv.Close()
	c, _ := NewClient(ClientOptions{MaxRetries: 5})
	if _, _, err := c.Do(context.Background(), "GET", srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("no retry expected on success, got %d calls", calls.Load())
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	c, _ := NewClient(ClientOptions{})
	if _, _, err := c.Do(ctx, "GET", "http://127.0.0.1:1/", nil); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
}

func TestNilClientRefused(t *testing.T) {
	var c *Client
	if _, _, err := c.Do(context.Background(), "GET", "http://127.0.0.1:1/", nil); err == nil {
		t.Fatal("nil client must refuse requests")
	}
}

func TestProxyOverrideApplies(t *testing.T) {
	var viaProxy atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Store(true)
		w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	c, err := NewClient(ClientOptions{Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	// The proxy can reach this host only through the configured proxy; use an
	// unreachable destination to prove the proxy did the work.
	_, body, err := c.Do(context.Background(), "GET", "http://192.0.2.10/", nil)
	if err != nil {
		t.Fatalf("proxy should have handled the request: %v", err)
	}
	if string(body) != "proxied" || !viaProxy.Load() {
		t.Fatalf("request did not go through the configured proxy")
	}
}
