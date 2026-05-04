package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"
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

	report := Run(context.Background(), runner, DefaultRegistry())
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
	if len(report.Results) != 3 {
		t.Fatalf("expected 3 sshd checks, got %d", len(report.Results))
	}

	if report.Modules[0].Detected {
		t.Fatal("expected sshd module to be reported as not detected")
	}

	if !report.Modules[0].Selected {
		t.Fatal("expected sshd module to be selected by all-modules mode")
	}

	if report.Meta["audit_mode"] != "all_modules" {
		t.Fatalf("unexpected audit mode: %s", report.Meta["audit_mode"])
	}

	if report.Summary["pass"] != 3 {
		t.Fatalf("expected 3 passing checks, got %d", report.Summary["pass"])
	}
}
