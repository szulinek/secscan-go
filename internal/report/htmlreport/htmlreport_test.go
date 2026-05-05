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
	mustContain(t, html, "PermitRootLogin is enabled")
	mustContain(t, html, "Disable direct root SSH login.")
	mustContain(t, html, "Technical details")

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

func renderTestReport(t *testing.T, reportType Type) string {
	t.Helper()

	modules := []audit.ModuleReport{
		{ID: "sshd", Name: "OpenSSH server", Detected: true, Selected: true},
		{ID: "nginx", Name: "Nginx", Detected: true, Selected: true},
	}
	report := audit.Report{
		Version:     "0.1.0",
		GeneratedAt: "2026-05-05T12:00:00Z",
		Host: system.Info{
			GOOS:      "linux",
			GOARCH:    "amd64",
			OSRelease: map[string]string{"PRETTY_NAME": "Debian GNU/Linux 12"},
		},
		Modules: modules,
		Inventory: audit.Inventory{
			Services: []system.Service{{Unit: "ssh.service", Active: "active", Sub: "running", Description: "OpenSSH server"}},
			Modules:  modules,
		},
		Results: []checks.Result{
			{
				ID:                   "sshd.permit_root_login",
				ModuleID:             "sshd",
				Service:              "sshd",
				Title:                "PermitRootLogin is enabled",
				Category:             checks.CategorySSH,
				Severity:             checks.SeverityHigh,
				Status:               checks.StatusFail,
				ClientSummary:        "Direct root login over SSH is enabled.",
				Recommendation:       "Disable direct root SSH login.",
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
