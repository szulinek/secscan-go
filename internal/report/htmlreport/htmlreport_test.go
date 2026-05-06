package htmlreport

import (
	"bytes"
	"strings"
	"testing"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/system"
)

func TestClientReportHidesInventoryAndInfo(t *testing.T) {
	html := renderTestReport(t, TypeClient)

	mustContain(t, html, "Security Audit Report")
	mustContain(t, html, "Executive Summary")
	mustContain(t, html, "Top Risks")
	mustContain(t, html, "server1.example.com / 203.0.113.10")
	mustContain(t, html, "PermitRootLogin is enabled")
	mustContain(t, html, "Disable direct root SSH login.")
	mustContain(t, html, "Technical details")
	mustContain(t, html, "Remediation steps")
	mustContain(t, html, "Edit /etc/ssh/sshd_config.")
	mustContain(t, html, "References")
	mustContain(t, html, "https://man.openbsd.org/sshd_config")
	mustContain(t, html, "Automation snippets")
	mustContain(t, html, "sshd -t")
	mustContain(t, html, "Detected public ports")
	mustContain(t, html, "8080/tcp")
	mustContain(t, html, "8443/tcp")
	mustContain(t, html, "devsrv")

	mustNotContain(t, html, "Admin Inventory")
	mustNotContain(t, html, "ssh.service")
	mustNotContain(t, html, "Service detected")
	mustNotContain(t, html, "PasswordAuthentication is disabled")
	mustNotContain(t, html, "Could not read effective sshd configuration.")
}

func TestAdminReportShowsInventoryAndPassingChecks(t *testing.T) {
	html := renderTestReport(t, TypeAdmin)

	mustContain(t, html, "Security Audit Report - Admin")
	mustContain(t, html, "Admin Inventory")
	mustContain(t, html, "ssh.service")
	mustContain(t, html, "Passing checks (1)")
	mustContain(t, html, "PasswordAuthentication is disabled")
	mustContain(t, html, "fail 1")
	mustContain(t, html, "warn 1")
	mustContain(t, html, "pass 1")
	mustContain(t, html, "Could not read effective sshd configuration.")

	mustNotContain(t, html, "Service detected")
}

func TestOpenPortsParserIgnoresNonPortEvidence(t *testing.T) {
	ports := openPorts(checks.Result{
		ID:       "linux.listening_ports",
		Evidence: "tcp/0.0.0.0/8080/devsrv; public_listeners=none; udp/::/5353/-",
	})
	if len(ports) != 2 {
		t.Fatalf("expected two parsed ports, got %d", len(ports))
	}
	if ports[0].Label != "8080/tcp" || ports[0].Address != "0.0.0.0" || ports[0].Process != "devsrv" {
		t.Fatalf("unexpected first port: %#v", ports[0])
	}
	if ports[1].Label != "5353/udp" || ports[1].Address != "::" || ports[1].Process != "" {
		t.Fatalf("unexpected second port: %#v", ports[1])
	}

	if got := openPorts(checks.Result{ID: "nginx.server_tokens", Evidence: "tcp/0.0.0.0/8080/devsrv"}); len(got) != 0 {
		t.Fatalf("non-listening-port finding should not render ports: %#v", got)
	}
}

func renderTestReport(t *testing.T, reportType Type) string {
	t.Helper()

	modules := []audit.ModuleReport{
		{ID: "sshd", Name: "OpenSSH server", Detected: true, Selected: true},
		{ID: "linux", Name: "Linux baseline", Detected: true, Selected: true},
		{ID: "nginx", Name: "Nginx", Detected: true, Selected: true},
	}
	report := audit.Report{
		Version:     "0.1.0",
		GeneratedAt: "2026-05-05T12:00:00Z",
		Host: system.Info{
			Hostname:    "server1.example.com",
			IPAddresses: []string{"203.0.113.10"},
			GOOS:        "linux",
			GOARCH:      "amd64",
			OSRelease:   map[string]string{"PRETTY_NAME": "Debian GNU/Linux 12"},
		},
		Modules: modules,
		Inventory: audit.Inventory{
			Services: []system.Service{{Unit: "ssh.service", Active: "active", Sub: "running", Description: "OpenSSH server"}},
			Modules:  modules,
		},
		Results: []checks.Result{
			{
				ID:             "sshd.permit_root_login",
				ModuleID:       "sshd",
				Service:        "sshd",
				Title:          "PermitRootLogin is enabled",
				Category:       checks.CategorySSH,
				Severity:       checks.SeverityHigh,
				Status:         checks.StatusFail,
				ClientSummary:  "Direct root login over SSH is enabled.",
				Recommendation: "Disable direct root SSH login.",
				RemediationSteps: []string{
					"Edit /etc/ssh/sshd_config.",
					"Set PermitRootLogin no.",
					"Validate with sshd -t and reload sshd.",
				},
				References: []string{"https://man.openbsd.org/sshd_config"},
				Automation: checks.Automation{
					Shell:   "sudo sshd -t && sudo systemctl reload sshd",
					Ansible: "- name: Disable root SSH login",
					Chef:    "service 'sshd'",
				},
				Impact:               "Root SSH login increases the blast radius of credential theft.",
				Evidence:             "permitrootlogin=yes",
				AdminDetails:         "Checked with sshd -T.",
				HiddenInClientReport: false,
			},
			{
				ID:             "nginx.server_tokens",
				ModuleID:       "nginx",
				Service:        "nginx",
				Title:          "server_tokens is enabled",
				Category:       checks.CategoryWeb,
				Severity:       checks.SeverityMedium,
				Status:         checks.StatusWarn,
				ClientSummary:  "Nginx may expose version information.",
				Recommendation: "Set server_tokens off.",
				Evidence:       "server_tokens=on",
				AdminDetails:   "Checked with nginx -T.",
			},
			{
				ID:             "linux.listening_ports",
				ModuleID:       "linux",
				Service:        "linux",
				Title:          "Unexpected public listening ports detected",
				Category:       checks.CategoryFirewall,
				Severity:       checks.SeverityMedium,
				Status:         checks.StatusWarn,
				ClientSummary:  "Unexpected public listening ports are exposed.",
				Recommendation: "Close unnecessary public listeners or document and firewall them explicitly.",
				Evidence:       "tcp/0.0.0.0/8080/devsrv; tcp/::/8443/proxy",
				AdminDetails:   "Collected with ss -tulpn.",
			},
			{
				ID:             "sshd.password_authentication",
				ModuleID:       "sshd",
				Service:        "sshd",
				Title:          "PasswordAuthentication is disabled",
				Category:       checks.CategorySSH,
				Severity:       checks.SeverityMedium,
				Status:         checks.StatusPass,
				ClientSummary:  "SSH password login is disabled.",
				Recommendation: "Keep password SSH login disabled.",
				Evidence:       "passwordauthentication=no",
			},
			{
				ID:                   "nginx.service_detected",
				ModuleID:             "nginx",
				Service:              "nginx",
				Title:                "Service detected",
				Category:             checks.CategoryWeb,
				Severity:             checks.SeverityInfo,
				Status:               checks.StatusInfo,
				ClientSummary:        "Nginx was detected.",
				HiddenInClientReport: true,
			},
			{
				ID:                   "sshd.config_error",
				ModuleID:             "sshd",
				Service:              "sshd",
				Title:                "Could not read effective sshd configuration.",
				Category:             checks.CategorySSH,
				Severity:             checks.SeverityHigh,
				Status:               checks.StatusError,
				ClientSummary:        "SSH security settings could not be verified.",
				Recommendation:       "Run the audit with access to sshd -T.",
				Evidence:             "sshd -T failed",
				AdminDetails:         "sshd -T returned an error.",
				HiddenInClientReport: true,
			},
		},
	}

	var out bytes.Buffer
	if err := Render(&out, report, reportType); err != nil {
		t.Fatalf("render report: %v", err)
	}
	return out.String()
}

func mustContain(t *testing.T, value, needle string) {
	t.Helper()
	if !strings.Contains(value, needle) {
		t.Fatalf("expected output to contain %q", needle)
	}
}

func mustNotContain(t *testing.T, value, needle string) {
	t.Helper()
	if strings.Contains(value, needle) {
		t.Fatalf("expected output not to contain %q", needle)
	}
}
