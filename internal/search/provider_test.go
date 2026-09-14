package search_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/internal/search"
)

func TestAPIProviderGET(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		if gotQuery == "" {
			gotQuery = r.URL.Query().Get("query")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[
			{"url":"https://blog.example.com/p.pdf","title":"P","snippet":"s"},
			{"url":"https://blog.example.com/p.pdf","title":"dup"}
		]}`))
	}))
	defer srv.Close()

	client, err := sources.NewClient(sources.ClientOptions{Timeout: 5 * time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p, err := search.NewAPIProvider(search.APIProviderOptions{
		Requester:  client,
		Name:       "test",
		Endpoint:   srv.URL + "/search",
		QueryParam: "q",
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	hits, err := p.Search(context.Background(), "site:*.example.com")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotQuery != "site:*.example.com" {
		t.Fatalf("query param = %q", gotQuery)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 deduplicated hit, got %d", len(hits))
	}
	if hits[0].Provider != "test" || hits[0].Title != "P" {
		t.Fatalf("unexpected hit: %+v", hits[0])
	}
}

func TestAPIProviderPOST(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		body = strings.TrimSpace(string(buf[:n]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"url":"https://docs.example.com/a"}]`))
	}))
	defer srv.Close()

	client, err := sources.NewClient(sources.ClientOptions{Timeout: 5 * time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p, err := search.NewAPIProvider(search.APIProviderOptions{
		Requester: client,
		Name:      "post",
		Endpoint:  srv.URL,
		Method:    "POST",
		Token:     "secret",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	hits, err := p.Search(context.Background(), "site:example.com")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if !strings.Contains(body, "site:example.com") {
		t.Fatalf("POST body = %q", body)
	}
}

func TestAPIProviderBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, err := sources.NewClient(sources.ClientOptions{Timeout: 5 * time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p, err := search.NewAPIProvider(search.APIProviderOptions{Requester: client, Endpoint: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewAPIProvider: %v", err)
	}
	_, err = p.Search(context.Background(), "q")
	if err == nil {
		t.Fatal("expected blocked error")
	}
	if be, ok := search.AsBlocked(err); !ok || be.Reason != "rate limited" {
		t.Fatalf("expected rate-limited BlockedError, got %v", err)
	}
}

func TestAPIProviderRejectsBadConfig(t *testing.T) {
	if _, err := search.NewAPIProvider(search.APIProviderOptions{Requester: nil, Endpoint: "https://x"}); err == nil {
		t.Fatal("nil requester should error")
	}
	if _, err := search.NewAPIProvider(search.APIProviderOptions{Requester: &fakeReq{}, Endpoint: "not a url"}); err == nil {
		t.Fatal("bad endpoint should error")
	}
	if _, err := search.NewAPIProvider(search.APIProviderOptions{Requester: &fakeReq{}, Endpoint: "file:///etc/passwd"}); err == nil {
		t.Fatal("file endpoint should error")
	}
	if _, err := search.NewAPIProvider(search.APIProviderOptions{Requester: &fakeReq{}, Endpoint: "https://x", Method: "DELETE"}); err == nil {
		t.Fatal("DELETE should error")
	}
}

type fakeReq struct{}

func (f *fakeReq) Do(ctx context.Context, method, u string, h http.Header) (*http.Response, []byte, error) {
	return nil, nil, nil
}
func (f *fakeReq) DoWithBody(ctx context.Context, method, u string, b []byte, h http.Header) (*http.Response, []byte, error) {
	return nil, nil, nil
}
