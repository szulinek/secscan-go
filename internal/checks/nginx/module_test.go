package nginx

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type mockRunner struct {
	outputs map[string]string
	counts  map[string]int
}

func (r *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[key]++
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("%s: executable file not found", name)
}

func TestParseConfig(t *testing.T) {
	config := ParseConfig(strings.Join([]string{
		"# server_tokens on;",
		`add_header X-Test "value # not comment"; # trailing comment`,
		"location ~ /\\. {",
		"  deny all;",
		"}",
	}, "\n"))

	if strings.Contains(config.Clean, "server_tokens on") {
		t.Fatalf("commented directive should be removed: %s", config.Clean)
	}
	if !strings.Contains(config.Clean, `"value # not comment"`) {
		t.Fatalf("quoted hash should be preserved: %s", config.Clean)
	}

	blocks := config.LocationBlocks()
	if len(blocks) != 1 {
		t.Fatalf("expected one location block, got %d", len(blocks))
	}
	if !containsHiddenFilePattern(blocks[0].Header) {
		t.Fatalf("expected hidden-file location header, got %q", blocks[0].Header)
	}
}

func TestServerTokensSetting(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   string
	}{
		{name: "off", config: "http { server_tokens off; }", want: "off"},
		{name: "on overrides", config: "http {\nserver_tokens off;\nserver {\nserver_tokens on;\n}\n}", want: "on"},
		{name: "comment ignored", config: "# server_tokens off;\nhttp { }", want: "default"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverTokensSetting(tc.config); got != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, got)
			}
		})
	}
}

func TestNginxChecksPassCase(t *testing.T) {
	config := strings.Join([]string{
		"http {",
		"  server_tokens off;",
		"  ssl_protocols TLSv1.2 TLSv1.3;",
		"  add_header X-Frame-Options SAMEORIGIN always;",
		"  add_header X-Content-Type-Options nosniff always;",
		"  add_header Referrer-Policy strict-origin-when-cross-origin always;",
		"  server {",
		"    listen 443 ssl;",
		"    server_name example.com;",
		"    root /opt/app/current/public;",
		"    location ~ /\\. { deny all; }",
		"  }",
		"}",
	}, "\n")

	for _, check := range []checks.Check{
		checkServerTokens{cache: &configCache{}},
		checkAutoindex{cache: &configCache{}},
		checkHiddenFilesAccess{cache: &configCache{}},
		checkDirectoryListingRisk{cache: &configCache{}},
		checkTLSProtocols{cache: &configCache{}},
		checkSecurityHeaders{cache: &configCache{}},
		checkDefaultVhost{cache: &configCache{}},
	} {
		result := check.Run(nginxContext(config))
		if result.Status != checks.StatusPass {
			t.Fatalf("%s expected pass, got %s (%s)", result.ID, result.Status, result.Evidence)
		}
		assertCompleteResult(t, result)
	}
}

func TestNginxChecksWarnAndFailCases(t *testing.T) {
	config := strings.Join([]string{
		"http {",
		"  server_tokens on;",
		"  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;",
		"  add_header X-Frame-Options SAMEORIGIN;",
		"  server {",
		"    listen 80 default_server;",
		"    server_name _;",
		"    root /var/www/html;",
		"    autoindex on;",
		"  }",
		"}",
	}, "\n")

	cases := []struct {
		check    checks.Check
		status   checks.Status
		severity checks.Severity
		evidence string
	}{
		{check: checkServerTokens{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityLow, evidence: "server_tokens=on"},
		{check: checkAutoindex{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityMedium, evidence: "autoindex on;"},
		{check: checkHiddenFilesAccess{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityHigh, evidence: "missing_protection=.git,.env,.ht"},
		{check: checkDirectoryListingRisk{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityMedium, evidence: "root=/var/www/html"},
		{check: checkTLSProtocols{cache: &configCache{}}, status: checks.StatusFail, severity: checks.SeverityHigh, evidence: "TLSv1"},
		{check: checkSecurityHeaders{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityMedium, evidence: "X-Frame-Options"},
		{check: checkDefaultVhost{cache: &configCache{}}, status: checks.StatusWarn, severity: checks.SeverityLow, evidence: "default_server"},
	}

	for _, tc := range cases {
		result := tc.check.Run(nginxContext(config))
		if result.Status != tc.status {
			t.Fatalf("%s expected %s, got %s (%s)", result.ID, tc.status, result.Status, result.Evidence)
		}
		if result.Severity != tc.severity {
			t.Fatalf("%s expected severity %s, got %s", result.ID, tc.severity, result.Severity)
		}
		assertCompleteResult(t, result)
		if !strings.Contains(result.Evidence, tc.evidence) {
			t.Fatalf("%s expected evidence to contain %q, got %q", result.ID, tc.evidence, result.Evidence)
		}
	}
}

func TestSecurityHeadersFailWhenMissing(t *testing.T) {
	result := checkSecurityHeaders{cache: &configCache{}}.Run(nginxContext("http { server { listen 80; } }"))
	if result.Status != checks.StatusFail {
		t.Fatalf("expected fail status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "headers=none" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestTLSProtocolsWarnWhenMissing(t *testing.T) {
	result := checkTLSProtocols{cache: &configCache{}}.Run(nginxContext("http { server { listen 443 ssl; } }"))
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "ssl_protocols=not_found" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestNginxTOutputIsCachedAcrossModuleChecks(t *testing.T) {
	config := strings.Join([]string{
		"http {",
		"  server_tokens off;",
		"  ssl_protocols TLSv1.2 TLSv1.3;",
		"  add_header X-Frame-Options SAMEORIGIN;",
		"  add_header X-Content-Type-Options nosniff;",
		"  add_header Referrer-Policy same-origin;",
		"  location ~ /\\. { deny all; }",
		"}",
	}, "\n")
	runner := &mockRunner{outputs: map[string]string{"nginx -T": config}}
	ctx := checks.Context{
		Context:  context.Background(),
		Runner:   runner,
		Services: []system.Service{{Unit: "nginx.service"}},
	}

	for _, check := range NewModule().Checks() {
		result := check.Run(ctx)
		assertCompleteResult(t, result)
	}

	if got := runner.counts["nginx -T"]; got != 1 {
		t.Fatalf("expected nginx -T to run once, got %d", got)
	}
}

func nginxContext(config string) checks.Context {
	return checks.Context{
		Context: context.Background(),
		Runner: &mockRunner{outputs: map[string]string{
			"nginx -T": config,
		}},
		Services: []system.Service{{Unit: "nginx.service"}},
	}
}

func assertCompleteResult(t *testing.T, result checks.Result) {
	t.Helper()
	missing := []string{}
	if result.Category == "" {
		missing = append(missing, "category")
	}
	if result.Severity == "" {
		missing = append(missing, "severity")
	}
	if result.Status == "" {
		missing = append(missing, "status")
	}
	if result.Title == "" {
		missing = append(missing, "title")
	}
	if result.Summary == "" {
		missing = append(missing, "summary")
	}
	if result.ClientSummary == "" {
		missing = append(missing, "client_summary")
	}
	if result.AdminDetails == "" {
		missing = append(missing, "admin_details")
	}
	if result.Impact == "" {
		missing = append(missing, "impact")
	}
	if result.Recommendation == "" {
		missing = append(missing, "recommendation")
	}
	if result.Remediation == "" {
		missing = append(missing, "remediation")
	}
	if result.Evidence == "" {
		missing = append(missing, "evidence")
	}
	if len(missing) > 0 {
		t.Fatalf("%s missing fields: %s", result.ID, strings.Join(missing, ", "))
	}
}
