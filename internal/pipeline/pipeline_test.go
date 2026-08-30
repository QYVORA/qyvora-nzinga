package pipeline

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-nzinga/internal/config"
	"github.com/QYVORA/qyvora-nzinga/internal/core"
	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func testEnv(t *testing.T, typ models.TargetType, value string) (*core.Env, *bytes.Buffer) {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	reg := sources.NewRegistry(
		sources.NewCrtSh(nil),
		sources.NewDNS(),
		sources.NewWhois(43),
		sources.NewGitHub(nil, ""),
		sources.NewSimulation(),
	)
	return &core.Env{
		Registry: reg,
		Config:   cfg,
		Events:   events.NewStream(&buf),
		Offline:  true,
	}, &buf
}

func runOnce(t *testing.T, target *models.Target) (*models.Session, *bytes.Buffer, error) {
	t.Helper()
	env, buf := testEnv(t, target.Type, target.Value)
	sess := models.NewSession()
	sess.TargetID = target.ID
	sess.Target = target.TypedName()
	env.Session = sess
	env.Target = target
	err := (&Runner{}).Run(context.Background(), env)
	return sess, buf, err
}

func TestRunnerRunsStagesInOrder(t *testing.T) {
	sess, _, err := runOnce(t, &models.Target{ID: "tgt-1", Type: models.TargetDomain, Value: "example.com", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.Stages) != len(StageOrder) {
		t.Fatalf("expected %d stages, got %d: %v", len(StageOrder), len(sess.Stages), sess.Stages)
	}
	for i, want := range StageOrder {
		if sess.Stages[i] != want {
			t.Fatalf("stage order mismatch at %d: got %q want %q", i, sess.Stages[i], want)
		}
	}
}

func TestRunnerEmitsContractedEvents(t *testing.T) {
	env, buf := testEnv(t, models.TargetDomain, "example.com")
	sess := models.NewSession()
	sess.TargetID = "tgt-1"
	env.Session = sess
	env.Target = &models.Target{ID: "tgt-1", Type: models.TargetDomain, Value: "example.com"}
	if err := (&Runner{}).Run(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	lines := buf.String()
	for _, want := range []string{`"schema_version":"1.0"`, `"framework":"nzinga"`, events.ScanStarted, events.ScanCompleted} {
		if !strings.Contains(lines, want) {
			t.Fatalf("event stream missing %q", want)
		}
	}
}

func TestRunnerSingleDomainProducesWildcardFinding(t *testing.T) {
	sess, _, err := runOnce(t, &models.Target{ID: "tgt-1", Type: models.TargetDomain, Value: "example.com", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range sess.Findings {
		if f.RuleID == "OSINT-004" {
			found = true
		}
	}
	if !found {
		t.Fatal("example.com demo target should produce the DNS wildcard finding")
	}
	if sess.RiskScore <= 0 || sess.RiskScore > 100 {
		t.Fatalf("risk out of range: %d", sess.RiskScore)
	}
	if sess.RiskLevel == "" {
		t.Fatal("risk level must be set")
	}
}

func TestRunnerOfflineTargetWithoutNetwork(t *testing.T) {
	sess, _, err := runOnce(t, &models.Target{ID: "tgt-2", Type: models.TargetIP, Value: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.IPs) != 1 || sess.IPs[0].Address != "203.0.113.10" {
		t.Fatalf("ip target should resolve to its own entity, got %+v", sess.IPs)
	}
}

func TestRunnerNilSessionRefused(t *testing.T) {
	env, _ := testEnv(t, models.TargetDomain, "example.com")
	env.Session = nil
	if err := (&Runner{}).Run(context.Background(), env); err == nil {
		t.Fatal("a session is required")
	}
}

func TestRunnerInvalidIPTargetRejected(t *testing.T) {
	env, _ := testEnv(t, models.TargetIP, "not-an-ip")
	sess := models.NewSession()
	sess.TargetID = "tgt-3"
	env.Session = sess
	if err := (&Runner{}).Run(context.Background(), env); err == nil {
		t.Fatal("an invalid ip target must fail the run")
	}
}

func TestStageOrderIsStable(t *testing.T) {
	got := strings.Join(StageOrder, " > ")
	want := "discover > collect > normalize > correlate > analyze > validate > report"
	if got != want {
		t.Fatalf("stage order changed: %s", got)
	}
}
