package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/checks/ssh"
)

type fakeRunner map[string]string

func (r fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	output, ok := r[key]
	if !ok {
		return nil, fmt.Errorf("unexpected command: %s", key)
	}

	return []byte(output), nil
}

func TestRunExecutesSSHDChecksWhenServiceDetected(t *testing.T) {
	runner := fakeRunner{
		"systemctl list-units --type=service --state=running --no-legend --no-pager --plain": "ssh.service loaded active running OpenBSD Secure Shell server\n",
		"sshd -T": strings.Join([]string{
			"permitrootlogin no",
			"passwordauthentication yes",
			"permitemptypasswords no",
		}, "\n"),
	}

	report := Run(context.Background(), runner, checks.NewRegistry(ssh.NewModule()))
	if len(report.Results) != 3 {
		t.Fatalf("expected 3 sshd checks, got %d", len(report.Results))
	}

	if !report.Modules[0].Selected {
		t.Fatal("expected detected sshd module to be selected")
	}

	if report.Summary["pass"] != 2 {
		t.Fatalf("expected 2 passing checks, got %d", report.Summary["pass"])
	}

	if report.Summary["warn"] != 1 {
		t.Fatalf("expected 1 warning check, got %d", report.Summary["warn"])
	}

	if report.Score != 96 {
		t.Fatalf("expected score 96, got %d", report.Score)
	}
}

func TestRunWithOptionsExecutesAllModulesWhenServiceIsNotDetected(t *testing.T) {
	runner := fakeRunner{
		"systemctl list-units --type=service --state=running --no-legend --no-pager --plain": "",
		"sshd -T": strings.Join([]string{
			"permitrootlogin no",
			"passwordauthentication no",
			"permitemptypasswords no",
		}, "\n"),
	}

	report := RunWithOptions(context.Background(), runner, DefaultRegistry(), Options{AllModules: true})
	if len(report.Modules) != 12 {
		t.Fatalf("expected 12 modules, got %d", len(report.Modules))
	}

	if len(report.Results) != 16 {
		t.Fatalf("expected 16 checks, got %d", len(report.Results))
	}

	if report.Modules[1].Detected {
		t.Fatal("expected sshd module to be reported as not detected")
	}

	if !report.Modules[1].Selected {
		t.Fatal("expected sshd module to be selected by all-modules mode")
	}

	if report.Meta["audit_mode"] != "all_modules" {
		t.Fatalf("unexpected audit mode: %s", report.Meta["audit_mode"])
	}

	if report.Summary["pass"] != 3 {
		t.Fatalf("expected 3 passing ssh checks, got %d", report.Summary["pass"])
	}
}

func TestPrepareReportScoresAndClassifiesFindings(t *testing.T) {
	report := Report{
		Results: []checks.Result{
			{
				ID:       "critical.fail",
				ModuleID: "x",
				Title:    "Critical failure",
				Category: checks.CategorySystem,
				Severity: checks.SeverityCritical,
				Status:   checks.StatusFail,
				Summary:  "critical",
			},
			{
				ID:       "high.warn",
				ModuleID: "x",
				Title:    "High warning",
				Category: checks.CategorySystem,
				Severity: checks.SeverityHigh,
				Status:   checks.StatusWarn,
				Summary:  "warning",
			},
			{
				ID:                   "hidden.fail",
				ModuleID:             "x",
				Title:                "Hidden failure",
				Category:             checks.CategorySystem,
				Severity:             checks.SeverityLow,
				Status:               checks.StatusFail,
				Summary:              "hidden",
				HiddenInClientReport: true,
			},
			{
				ID:       "info",
				ModuleID: "x",
				Title:    "Info",
				Category: checks.CategorySystem,
				Severity: checks.SeverityInfo,
				Status:   checks.StatusInfo,
				Summary:  "info",
			},
		},
	}

	PrepareReport(&report)
	if report.Score != 65 {
		t.Fatalf("expected score 65, got %d", report.Score)
	}
	if len(report.TopFindings) != 3 {
		t.Fatalf("expected 3 top findings, got %d", len(report.TopFindings))
	}
	if len(report.ClientFindings) != 2 {
		t.Fatalf("expected 2 client findings, got %d", len(report.ClientFindings))
	}
	if len(report.AdminFindings) != 4 {
		t.Fatalf("expected 4 admin findings, got %d", len(report.AdminFindings))
	}
	if report.SeverityCounts["critical"] != 1 || report.SeverityCounts["high"] != 1 || report.SeverityCounts["low"] != 1 {
		t.Fatalf("unexpected severity counts: %#v", report.SeverityCounts)
	}
}
