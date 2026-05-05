package batchreport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/report/htmlreport"
	"secscan/internal/system"
)

func TestLoadReportsSortsJSONFiles(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, filepath.Join(dir, "b.json"), sampleReport("host-b", "192.0.2.20", 90))
	writeReport(t, filepath.Join(dir, "a.json"), sampleReport("host-a", "192.0.2.10", 80))
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("ignored"), 0600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	reports, err := LoadReports(dir)
	if err != nil {
		t.Fatalf("load reports: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[0].Host.Hostname != "host-a" || reports[1].Host.Hostname != "host-b" {
		t.Fatalf("reports not sorted by filename: %s, %s", reports[0].Host.Hostname, reports[1].Host.Hostname)
	}
}

func TestRenderBatchReportIncludesHostTableAndRisks(t *testing.T) {
	reports := []audit.Report{
		sampleReport("host-a", "192.0.2.10", 90),
		sampleReport("host-b", "192.0.2.20", 70),
	}

	var out bytes.Buffer
	if err := Render(&out, reports, htmlreport.TypeClient); err != nil {
		t.Fatalf("render batch report: %v", err)
	}

	html := out.String()
	for _, needle := range []string{
		"Security Audit Batch Report",
		"Host Summary",
		"Host Sections",
		"host-a",
		"192.0.2.10",
		"PermitRootLogin is enabled",
		"Module summary",
	} {
		if !strings.Contains(html, needle) {
			t.Fatalf("expected output to contain %q", needle)
		}
	}
}

func writeReport(t *testing.T, path string, report audit.Report) {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

func sampleReport(hostname, ip string, score int) audit.Report {
	report := audit.Report{
		Version:     "0.1.0",
		GeneratedAt: "2026-05-05T12:00:00Z",
		Host: system.Info{
			Hostname:    hostname,
			IPAddresses: []string{ip},
			GOOS:        "linux",
			GOARCH:      "amd64",
			OSRelease:   map[string]string{"PRETTY_NAME": "Debian GNU/Linux 12"},
		},
		Modules: []audit.ModuleReport{{ID: "sshd", Name: "OpenSSH server", Detected: true, Selected: true}},
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
			},
		},
	}
	audit.PrepareReport(&report)
	report.Score = score
	return report
}
