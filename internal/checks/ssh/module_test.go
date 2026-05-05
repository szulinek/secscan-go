package ssh

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"secscan/internal/checks"
)

type fakeSSHDRunner struct {
	output string
}

func (r fakeSSHDRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "sshd" && strings.Join(args, " ") == "-T" {
		return []byte(r.output), nil
	}

	return nil, fmt.Errorf("unexpected command: %s %s", name, strings.Join(args, " "))
}

func TestParseSSHDConfig(t *testing.T) {
	values := parseSSHDConfig(`
permitrootlogin no
passwordauthentication yes
permitemptypasswords no
`)

	if values["permitrootlogin"] != "no" {
		t.Fatalf("unexpected permitrootlogin: %s", values["permitrootlogin"])
	}

	if values["passwordauthentication"] != "yes" {
		t.Fatalf("unexpected passwordauthentication: %s", values["passwordauthentication"])
	}

	if values["permitemptypasswords"] != "no" {
		t.Fatalf("unexpected permitemptypasswords: %s", values["permitemptypasswords"])
	}
}

func TestPermitRootLoginEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		status   checks.Status
		severity checks.Severity
		title    string
	}{
		{
			name:     "disabled",
			value:    "no",
			status:   checks.StatusPass,
			severity: checks.SeverityHigh,
			title:    "PermitRootLogin is disabled",
		},
		{
			name:     "key based",
			value:    "without-password",
			status:   checks.StatusWarn,
			severity: checks.SeverityMedium,
			title:    "PermitRootLogin allows key-based root login",
		},
		{
			name:     "enabled",
			value:    "yes",
			status:   checks.StatusFail,
			severity: checks.SeverityHigh,
			title:    "PermitRootLogin is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := checkPermitRootLogin{config: &EffectiveConfig{}}
			ctx := checks.Context{
				Context: context.Background(),
				Runner:  fakeSSHDRunner{output: "permitrootlogin " + tt.value},
			}

			result := check.Run(ctx)
			if result.Status != tt.status {
				t.Fatalf("expected status %s, got %s", tt.status, result.Status)
			}
			if result.Severity != tt.severity {
				t.Fatalf("expected severity %s, got %s", tt.severity, result.Severity)
			}
			if result.Title != tt.title {
				t.Fatalf("expected title %q, got %q", tt.title, result.Title)
			}
			if result.Evidence != "permitrootlogin="+tt.value {
				t.Fatalf("unexpected evidence: %s", result.Evidence)
			}
		})
	}
}
