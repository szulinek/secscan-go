package comparereport

import (
	"bytes"
	"strings"
	"testing"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/system"
)

func TestCompareDetectsAddedFinding(t *testing.T) {
	previous := sampleReport()
	current := sampleReport(result("ssh.password", checks.SeverityMedium, checks.StatusWarn, "passwordauthentication yes"))

	compare := Compare(previous, current)
	if len(compare.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(compare.NewFindings))
	}
	if compare.NewFindings[0].ID != "ssh.password" {
		t.Fatalf("unexpected new finding: %s", compare.NewFindings[0].ID)
	}
}

func TestCompareDetectsResolvedFinding(t *testing.T) {
	previous := sampleReport(result("ssh.password", checks.SeverityMedium, checks.StatusWarn, "passwordauthentication yes"))
	current := sampleReport()

	compare := Compare(previous, current)
	if len(compare.ResolvedFindings) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(compare.ResolvedFindings))
	}
	if compare.ResolvedFindings[0].ID != "ssh.password" {
		t.Fatalf("unexpected resolved finding: %s", compare.ResolvedFindings[0].ID)
	}
}

func TestCompareDetectsChangedFinding(t *testing.T) {
	previous := sampleReport(result("nginx.server_tokens", checks.SeverityLow, checks.StatusWarn, "server_tokens on"))
	current := sampleReport(result("nginx.server_tokens", checks.SeverityLow, checks.StatusPass, "server_tokens off"))

	compare := Compare(previous, current)
	if len(compare.ChangedFindings) != 1 {
		t.Fatalf("expected 1 changed finding, got %d", len(compare.ChangedFindings))
	}
	changed := compare.ChangedFindings[0]
	if changed.ID != "nginx.server_tokens" {
		t.Fatalf("unexpected changed finding: %s", changed.ID)
	}
	if !changed.StatusChanged || !changed.EvidenceChanged {
		t.Fatalf("expected status and evidence change, got %#v", changed)
	}
	if changed.SeverityChanged {
		t.Fatalf("did not expect severity change")
	}
}

func TestCompareCalculatesScoreDelta(t *testing.T) {
	previous := sampleReport()
	current := sampleReport(result("ssh.root", checks.SeverityHigh, checks.StatusFail, "permitrootlogin yes"))

	compare := Compare(previous, current)
	if compare.PreviousScore != 100 {
		t.Fatalf("expected previous score 100, got %d", compare.PreviousScore)
	}
	if compare.CurrentScore != 85 {
		t.Fatalf("expected current score 85, got %d", compare.CurrentScore)
	}
	if compare.ScoreDelta != -15 {
		t.Fatalf("expected score delta -15, got %d", compare.ScoreDelta)
	}
}

func TestCompareCalculatesModuleSummaryDelta(t *testing.T) {
	previous := sampleReport(result("ssh.root", checks.SeverityHigh, checks.StatusPass, "permitrootlogin no"))
	current := sampleReport(
		result("ssh.root", checks.SeverityHigh, checks.StatusFail, "permitrootlogin yes"),
		result("nginx.server_tokens", checks.SeverityLow, checks.StatusWarn, "server_tokens on"),
	)

	compare := Compare(previous, current)
	ssh := findModuleDelta(t, compare.ModuleDelta, "ssh")
	if ssh.FailDelta != 1 || ssh.PassDelta != -1 {
		t.Fatalf("unexpected ssh module delta: %#v", ssh)
	}
	nginx := findModuleDelta(t, compare.ModuleDelta, "nginx")
	if nginx.WarnDelta != 1 {
		t.Fatalf("unexpected nginx module delta: %#v", nginx)
	}
}

func TestRenderIncludesCompareSections(t *testing.T) {
	previous := sampleReport()
	current := sampleReport(result("ssh.root", checks.SeverityHigh, checks.StatusFail, "permitrootlogin yes"))

	var html bytes.Buffer
	if err := Render(&html, previous, current); err != nil {
		t.Fatalf("render compare report: %v", err)
	}

	output := html.String()
	for _, expected := range []string{"Score trend", "Module trend", "New findings", "Resolved findings", "Changed findings"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func sampleReport(results ...checks.Result) audit.Report {
	report := audit.Report{
		Tool:        audit.ToolName,
		Version:     audit.Version,
		GeneratedAt: "2026-05-07T12:00:00Z",
		Host: system.Info{
			Hostname:    "host-a",
			IPAddresses: []string{"192.0.2.10"},
		},
		Modules: []audit.ModuleReport{
			{ID: "ssh", Name: "SSH", Detected: true, Selected: true},
			{ID: "nginx", Name: "Nginx", Detected: true, Selected: true},
		},
		Inventory: audit.Inventory{
			Modules: []audit.ModuleReport{
				{ID: "ssh", Name: "SSH", Detected: true, Selected: true},
				{ID: "nginx", Name: "Nginx", Detected: true, Selected: true},
			},
		},
		Results: results,
	}
	audit.PrepareReport(&report)
	return report
}

func result(id string, severity checks.Severity, status checks.Status, evidence string) checks.Result {
	moduleID := "ssh"
	if strings.HasPrefix(id, "nginx.") {
		moduleID = "nginx"
	}
	return checks.Result{
		ID:             id,
		ModuleID:       moduleID,
		Service:        moduleID,
		Title:          id,
		Category:       checks.CategorySystem,
		Severity:       severity,
		Status:         status,
		Summary:        id,
		ClientSummary:  id,
		AdminDetails:   id,
		Impact:         "impact",
		Recommendation: "recommendation",
		Evidence:       evidence,
	}
}

func findModuleDelta(t *testing.T, deltas []ModuleDelta, moduleID string) ModuleDelta {
	t.Helper()
	for _, delta := range deltas {
		if delta.ModuleID == moduleID {
			return delta
		}
	}
	t.Fatalf("missing module delta for %s in %#v", moduleID, deltas)
	return ModuleDelta{}
}
