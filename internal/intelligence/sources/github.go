package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// GitHub queries GitHub's public API for profile and repository metadata. It
// works without a token (shared, low rate limit) and honours an optional
// configured token for authenticated rate limits. Only public endpoints are
// used.
type GitHub struct {
	client *Client
	token  string
}

// NewGitHub returns the GitHub source.
func NewGitHub(client *Client, token string) *GitHub {
	return &GitHub{client: client, token: token}
}

// ID implements Source.
func (g *GitHub) ID() string { return "github" }

// Name implements Source.
func (g *GitHub) Name() string { return "GitHub public API" }

// Capabilities implements Source.
func (g *GitHub) Capabilities() []models.Capability {
	return []models.Capability{models.CapUsernameLookup, models.CapRepoEnumerate}
}

// Describe implements Source.
func (g *GitHub) Describe() models.Source {
	return models.Source{
		ID:           "github",
		Name:         "GitHub public API",
		Description:  "Public user/org profiles and public repository enumeration via api.github.com",
		Category:     models.CategoryCode,
		Capabilities: g.Capabilities(),
		Output:       []models.NodeKind{models.NodeUsername, models.NodeSocialAccount, models.NodeRepository, models.NodeEmail},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetUsername, models.TargetOrganization},
		RateLimit:    "60 req/h unauthenticated; configure a token to raise it",
		Notes:        "Public data only; the framework records exactly what the API returns.",
	}
}

type ghUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Company  string `json:"company"`
	Blog     string `json:"blog"`
	Location string `json:"location"`
	Email    string `json:"email"`
	HTMLURL  string `json:"html_url"`
}

type ghRepo struct {
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Stargazers  int    `json:"stargazers_count"`
	HTMLURL     string `json:"html_url"`
}

// Collect implements Source.
func (g *GitHub) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if g.client == nil {
		return nil, fmt.Errorf("github client is unavailable (see logs)")
	}
	switch t.Type {
	case models.TargetUsername:
		return g.collectUser(ctx, t.Value)
	case models.TargetOrganization:
		return g.collectOrg(ctx, t.Value)
	default:
		return nil, nil
	}
}

func (g *GitHub) collectUser(ctx context.Context, handle string) ([]*models.Observation, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return nil, fmt.Errorf("empty username")
	}

	var out []*models.Observation
	now := time.Now().UTC()

	var u ghUser
	if err := g.getJSON(ctx, "https://api.github.com/users/"+handle, &u); err != nil {
		return nil, err
	}
	if u.HTMLURL == "" && u.Login == "" {
		return nil, fmt.Errorf("github returned no profile for %q", handle)
	}

	emit := func(key, target, value string, raw map[string]string) {
		out = append(out, &models.Observation{
			ID:         models.NewID("obs"),
			Source:     "github",
			Capability: models.CapUsernameLookup,
			Target:     target,
			Key:        key,
			Value:      value,
			State:      models.StateObserved,
			Confidence: models.ConfidenceObserved,
			Raw:        raw,
			Timestamp:  now,
		})
	}

	login := u.Login
	if login == "" {
		login = handle
	}
	profile := map[string]string{"url": fixedURL(u.HTMLURL, "https://github.com/"+login)}
	emit("username", "github", login, profile)
	emit("social_url", login, fixedURL(u.HTMLURL, "https://github.com/"+login), map[string]string{"platform": "github"})
	if u.Name != "" {
		emit("person_name", login, u.Name, profile)
	}
	if u.Company != "" {
		emit("github_company", login, u.Company, profile)
	}
	if u.Email != "" {
		emit("email", login, strings.ToLower(u.Email), profile)
	}

	// Public repositories for the account.
	var repos []ghRepo
	if err := g.getJSON(ctx, "https://api.github.com/users/"+login+"/repos?per_page=100", &repos); err != nil {
		// Repo enumeration failing is not fatal to profile collection; the
		// framework records the honest partial result, never a fabrication.
		return out, nil
	}
	for _, r := range repos {
		emit("repo", login, r.FullName, map[string]string{
			"url":         r.HTMLURL,
			"stars":       fmt.Sprintf("%d", r.Stargazers),
			"description": truncate(r.Description, 200),
		})
	}
	return out, nil
}

func (g *GitHub) collectOrg(ctx context.Context, name string) ([]*models.Observation, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("empty organization")
	}
	var out []*models.Observation
	now := time.Now().UTC()

	var u ghUser
	if err := g.getJSON(ctx, "https://api.github.com/orgs/"+name, &u); err != nil {
		return nil, err
	}
	emit := func(key, target, value string, raw map[string]string) {
		out = append(out, &models.Observation{
			ID:         models.NewID("obs"),
			Source:     "github",
			Capability: models.CapRepoEnumerate,
			Target:     target,
			Key:        key,
			Value:      value,
			State:      models.StateObserved,
			Confidence: models.ConfidenceObserved,
			Raw:        raw,
			Timestamp:  now,
		})
	}
	login := u.Login
	if login == "" {
		login = name
	}
	emit("github_org", "github", login, map[string]string{"url": fixedURL(u.HTMLURL, "https://github.com/"+login)})
	if u.Name != "" && u.Name != login {
		emit("github_org_name", login, u.Name, nil)
	}

	var repos []ghRepo
	if err := g.getJSON(ctx, "https://api.github.com/orgs/"+login+"/repos?per_page=100", &repos); err != nil {
		return out, nil
	}
	for _, r := range repos {
		emit("repo", login, r.FullName, map[string]string{
			"url":         r.HTMLURL,
			"stars":       fmt.Sprintf("%d", r.Stargazers),
			"description": truncate(r.Description, 200),
		})
	}
	return out, nil
}

func (g *GitHub) getJSON(ctx context.Context, u string, v any) error {
	headers := http.Header{"Accept": {"application/vnd.github+json"}, "User-Agent": {"QYVORA-NZINGA"}}
	if g.token != "" {
		headers.Set("Authorization", "Bearer "+g.token)
	}
	resp, body, err := g.client.Do(ctx, http.MethodGet, u, headers)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github returned status %d for %s", resp.StatusCode, u)
	}
	return json.Unmarshal(body, v)
}

// Simulate implements Source: mirrors the offline dataset.
func (g *GitHub) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	switch t.Type {
	case models.TargetUsername:
		return simulatedUserObservations(t.Value), nil
	case models.TargetOrganization:
		return simulatedOrgObservations(foldOrg(t.Value)), nil
	default:
		return nil, nil
	}
}

func fixedURL(raw, fallback string) string {
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return raw
	}
	return fallback
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
