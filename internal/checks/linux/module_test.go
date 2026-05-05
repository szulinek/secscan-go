package linux

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type mockRunner struct {
	outputs map[string]string
	errors  map[string]error
}

func (r mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if err, ok := r.errors[key]; ok {
		return nil, err
	}
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("%s: executable file not found", name)
}

func TestIPTablesLooksConfigured(t *testing.T) {
	if iptablesLooksConfigured("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n") {
		t.Fatal("default ACCEPT policies should not be treated as configured firewall rules")
	}

	if !iptablesLooksConfigured("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n") {
		t.Fatal("DROP policy and explicit rules should be treated as configured firewall rules")
	}
}

func TestOSVersionCheck(t *testing.T) {
	result := checkOSVersion{}.Run(checks.Context{
		Host: system.Info{OSRelease: map[string]string{
			"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
			"VERSION_ID":       "12",
			"VERSION_CODENAME": "bookworm",
		}},
	})

	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	for _, needle := range []string{"PRETTY_NAME=Debian GNU/Linux 12 (bookworm)", "VERSION_ID=12", "VERSION_CODENAME=bookworm"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %q", needle, result.Evidence)
		}
	}
}

func TestKernelVersionCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner:  mockRunner{outputs: map[string]string{"uname -r": "6.1.0-25-amd64\n"}},
	}

	result := checkKernelVersion{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	if result.Evidence != "kernel=6.1.0-25-amd64" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{errors: map[string]error{"uname -r": errors.New("permission denied")}}
	result = checkKernelVersion{}.Run(ctx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status, got %s", result.Status)
	}
	if result.Evidence != "uname -r failed" {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
}

func TestSecurityUpdatesAvailableCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"apt-get -s -o Debug::NoLocking=true upgrade": strings.Join([]string{
				"Inst openssl [1.1] (1.2 Debian-Security:12/stable-security [amd64])",
				"Inst nginx [1.22] (1.24 Debian:12/stable [amd64])",
			}, "\n"),
		}},
	}

	result := checkSecurityUpdatesAvailable{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	if result.Evidence != "security_updates=1" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{outputs: map[string]string{"apt-get -s -o Debug::NoLocking=true upgrade": "0 upgraded, 0 newly installed\n"}}
	result = checkSecurityUpdatesAvailable{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	if result.Evidence != "security_updates=0" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}
}

func TestFirewallStatusPassWarnError(t *testing.T) {
	base := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
	}

	passCtx := base
	passCtx.Services = []system.Service{{Unit: "nftables.service"}}
	passCtx.Runner = mockRunner{}
	result := checkFirewallStatus{}.Run(passCtx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "running_service=nftables.service") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	warnCtx := base
	warnCtx.Runner = mockRunner{outputs: map[string]string{
		"ufw status":       "Status: inactive\n",
		"nft list ruleset": "",
		"iptables -S":      "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
	}}
	result = checkFirewallStatus{}.Run(warnCtx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	if result.Evidence != "firewall=not_detected" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}

	errorCtx := base
	errorCtx.Runner = mockRunner{errors: map[string]error{
		"ufw status":       errors.New("permission denied"),
		"nft list ruleset": errors.New("permission denied"),
		"iptables -S":      errors.New("permission denied"),
	}}
	result = checkFirewallStatus{}.Run(errorCtx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "ufw=probe_error") {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
}

func TestProtectionDaemonPassWarn(t *testing.T) {
	ctx := checks.Context{
		Context:  context.Background(),
		Host:     linuxHost(),
		Services: []system.Service{{Unit: "fail2ban.service"}},
	}

	result := checkProtectionDaemon{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	if result.Evidence != "running_service=fail2ban.service" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	ctx.Services = nil
	result = checkProtectionDaemon{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	if result.Evidence != "protection_daemon=not_detected" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
}

func linuxHost() system.Info {
	return system.Info{
		GOOS: "linux",
		OSRelease: map[string]string{
			"ID":               "debian",
			"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
			"VERSION_ID":       "12",
			"VERSION_CODENAME": "bookworm",
		},
	}
}
