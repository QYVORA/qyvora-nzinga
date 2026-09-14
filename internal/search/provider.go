package search

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Provider executes a rendered dork query against one search surface. A
// provider returns typed errors: BlockedError when the surface challenged or
// rate-limited the operator (never bypassed), context errors for cancellations,
// and ordinary errors for transport/parse failures.
type Provider interface {
	// Name is the stable provider identifier, e.g. "simulation" or "api".
	Name() string
	// Search runs one rendered query and returns its hits.
	Search(ctx context.Context, query string) ([]Result, error)
}

// Result is one search hit returned by a provider. Fields other than URL are
// best-effort metadata; the framework treats a hit as an unverified reference
// to a page a search index claims exists.
type Result struct {
	// URL is the hit URL returned by the provider.
	URL string `json:"url"`
	// Title is the snippet/site title when the provider returns one.
	Title string `json:"title,omitempty"`
	// Snippet is the visible snippet the provider supplied, when any.
	Snippet string `json:"snippet,omitempty"`
	// Provider records the provider that returned the hit.
	Provider string `json:"provider,omitempty"`
	// Confidence is the truthfulness the framework assigns to the hit. The
	// search source normally overrides this to mark hits as unverified.
	Confidence models.Confidence `json:"confidence,omitempty"`
	// RawReference is a pointer to the raw record (e.g. provider query URL)
	// usable as provenance in evidence.
	RawReference string `json:"raw_reference,omitempty"`
}

// BlockedError reports that a search surface refused the request. The
// framework never attempts to defeat it; it reports and suggests a sanctioned
// resolution so operators know why a query surfaced nothing.
type BlockedError struct {
	// Provider that returned the block.
	Provider string
	// Reason is a short human description, e.g. "rate limited" or
	// "anti-automation challenge".
	Reason string
	// Recommended is the sanctioned way forward.
	Recommended string
}

func (e *BlockedError) Error() string {
	if e == nil {
		return "search surface blocked the request"
	}
	return fmt.Sprintf("search provider %q blocked the request: %s (recommended: %s)", e.Provider, e.Reason, e.Recommended)
}

// AsBlocked unwraps a BlockedError from err.
func AsBlocked(err error) (*BlockedError, bool) {
	var be *BlockedError
	if errors.As(err, &be) {
		return be, be != nil
	}
	return nil, false
}

// ClassifyBlocked inspects an HTTP response and returns a BlockedError when
// the surface is challenging, throttling, or denying the request. Detection is
// conservative: only clear signals map to a block, anything else is left for
// the caller to handle as a plain HTTP error.
func ClassifyBlocked(status int, body string) *BlockedError {
	switch status {
	case http.StatusTooManyRequests:
		return &BlockedError{
			Reason:      "rate limited",
			Recommended: "raise max_queries backoff, reduce sources.search.max_queries, or use a sanctioned provider",
		}
	case http.StatusForbidden:
		// A challenge wall reads 403: the body wins over the generic denial,
		// because bypassing an anti-automation wall is never an option.
		if isChallengeBody(body) {
			return &BlockedError{
				Reason:      "anti-automation challenge detected and not bypassed",
				Recommended: "use a sanctioned provider that allows machine queries, or reduce query volume",
			}
		}
		return &BlockedError{
			Reason:      "access denied",
			Recommended: "verify the provider token/endpoint or use the simulation provider",
		}
	case http.StatusUnauthorized:
		return &BlockedError{
			Reason:      "authentication required",
			Recommended: "configure a valid provider token",
		}
	case http.StatusNotImplemented, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &BlockedError{
			Reason:      "provider unavailable",
			Recommended: "retry later or switch provider",
		}
	}
	if isChallengeBody(body) {
		return &BlockedError{
			Reason:      "anti-automation challenge detected and not bypassed",
			Recommended: "use a sanctioned provider that allows machine queries, or reduce query volume",
		}
	}
	return nil
}

// antiBotMarkers are phrase-level signals that a page is a challenge/login
// wall rather than search results. Kept conservative so results pages are not
// misclassified.
var antiBotMarkers = []string{
	"unusual traffic",
	"not a robot",
	"captcha",
	"verify you are human",
	"access denied",
	"too many requests",
}

func isChallengeBody(body string) bool {
	lower := strings.ToLower(body)
	for _, m := range antiBotMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
