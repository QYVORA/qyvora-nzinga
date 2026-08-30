package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the shared hardened HTTP client used by every source. It applies
// the framework's defensive defaults even against its operator:
//
//   - every request carries a context that cancels on interruption/timeout;
//   - response bodies are capped (maxResponseBytes);
//   - off-origin redirects are refused unless explicitly enabled (SSRF guard);
//   - transient failures are retried a bounded number of times;
//   - an optional per-second rate limiter paces outbound requests.
type Client struct {
	http       *http.Client
	ua         string
	max        int64
	maxRetries int
	limiter    *Limiter
}

// ClientOptions configures the shared client.
type ClientOptions struct {
	Timeout          time.Duration
	UserAgent        string
	MaxResponseBytes int64
	FollowRedirects  bool
	Proxy            string
	MaxRetries       int
	RateLimitPerSec  float64
}

// NewClient builds a hardened HTTP client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = 1 << 20
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	}

	tp := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: opts.Timeout,
	}
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid http proxy: %w", err)
		}
		tp.Proxy = http.ProxyURL(pu)
	}

	client := &http.Client{
		Transport: tp,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			orig := via[0].URL
			if !sameOrigin(orig, req.URL) {
				return fmt.Errorf("refusing cross-origin redirect to %s (SSRF guard)", req.URL)
			}
			return nil
		},
	}

	return &Client{http: client, ua: opts.UserAgent, max: opts.MaxResponseBytes, maxRetries: opts.MaxRetries,
		limiter: newLimiter(opts.RateLimitPerSec)}, nil
}

// Do performs a request and returns the response with the full body read.
func (c *Client) Do(ctx context.Context, method, u string, headers http.Header) (*http.Response, []byte, error) {
	if c == nil || c.http == nil {
		return nil, nil, errors.New("http client is nil")
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, nil, err
	}
	if c.maxRetries > 0 && safeToRetry(method) {
		return c.doRetry(ctx, req, headers)
	}
	return c.doOnce(ctx, req, headers)
}

func (c *Client) doRetry(ctx context.Context, req *http.Request, headers http.Header) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		resp, body, err := c.doOnce(ctx, req, headers)
		if err == nil {
			// 429/5xx disable the body for retry accounting.
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
				_ = body
				continue
			}
			return resp, body, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, req *http.Request, headers http.Header) (*http.Response, []byte, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, nil, err
		}
	}
	req = req.Clone(ctx)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.ua != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.ua)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, c.max+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > c.max {
		return resp, nil, fmt.Errorf("response exceeds %d bytes cap", c.max)
	}
	return resp, body, nil
}

func safeToRetry(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func backoff(attempt int) time.Duration {
	// 250ms, 500ms, 1s, ... capped at 4s.
	d := 250 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= 4*time.Second {
			return 4 * time.Second
		}
	}
	return d
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Scheme == b.Scheme
}

// Limiter is a minimal token-bucket rate limiter (requests per second).
type Limiter struct {
	rate   float64       // tokens per second
	mu     chan struct{} // capacity = burst
	muLock bool
	tokens float64
	last   time.Time
}

func newLimiter(perSec float64) *Limiter {
	if perSec <= 0 {
		return nil
	}
	// Sneaky sizing: make each goroutine wait on a small semaphore while the
	// token bucket runs on a single goroutine-free clock.
	return &Limiter{rate: perSec, mu: make(chan struct{}, 1), muLock: true, tokens: perSec, last: time.Now()}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		l.mu <- struct{}{}
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.rate {
			l.tokens = l.rate
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			<-l.mu
			return nil
		}
		need := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		<-l.mu
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(need):
		}
	}
}
