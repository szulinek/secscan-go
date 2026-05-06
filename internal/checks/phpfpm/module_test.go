package phpfpm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type fixturePaths struct {
	root     string
	binary   string
	ini      string
	poolConf string
}

func TestDetectMatchesRunningService(t *testing.T) {
	ctx := checks.Context{
		Context:  context.Background(),
		Services: []system.Service{{Unit: "php82-fpm.service"}},
	}

	if !NewModule().Detect(ctx) {
		t.Fatal("expected php-fpm module to be detected by running service")
	}
}

func TestVersionCheckFindsDirectAdminBinaries(t *testing.T) {
	paths := withPHPFPMFixture(t, goodPHPINI(), goodPoolConfig("admin", "30"))
	result := checkVersion{cache: &discoveryCache{}}.Run(checks.Context{})

	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82="+paths.binary) {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestPHPINIHardeningChecksPass(t *testing.T) {
	withPHPFPMFixture(t, goodPHPINI(), goodPoolConfig("admin", "30"))
	ctx := checks.Context{Context: context.Background()}

	for _, check := range []checks.Check{
		checkExposePHP{cache: &discoveryCache{}},
		checkDisplayErrors{cache: &discoveryCache{}},
		checkDisableFunctions{cache: &discoveryCache{}},
		checkCGIFixPathInfo{cache: &discoveryCache{}},
	} {
		result := check.Run(ctx)
		if result.Status != checks.StatusPass {
			t.Fatalf("%s expected pass, got %s (%s)", result.ID, result.Status, result.Evidence)
		}
		assertCompleteResult(t, result)
	}
}

func TestPHPINIHardeningChecksWarn(t *testing.T) {
	withPHPFPMFixture(t, strings.Join([]string{
		"expose_php = On",
		"display_errors = On",
		"disable_functions =",
		"; cgi.fix_pathinfo intentionally missing",
	}, "\n"), goodPoolConfig("admin", "30"))
	ctx := checks.Context{Context: context.Background()}

	cases := []struct {
		check    checks.Check
		severity checks.Severity
		evidence string
	}{
		{check: checkExposePHP{cache: &discoveryCache{}}, severity: checks.SeverityLow, evidence: "expose_php=On"},
		{check: checkDisplayErrors{cache: &discoveryCache{}}, severity: checks.SeverityMedium, evidence: "display_errors=On"},
		{check: checkDisableFunctions{cache: &discoveryCache{}}, severity: checks.SeverityMedium, evidence: "disable_functions=empty"},
		{check: checkCGIFixPathInfo{cache: &discoveryCache{}}, severity: checks.SeverityMedium, evidence: "cgi.fix_pathinfo=missing(default 1)"},
	}

	for _, tc := range cases {
		result := tc.check.Run(ctx)
		if result.Status != checks.StatusWarn {
			t.Fatalf("%s expected warn, got %s (%s)", result.ID, result.Status, result.Evidence)
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

func TestPoolUserCheckPassAndFail(t *testing.T) {
	paths := withPHPFPMFixture(t, goodPHPINI(), goodPoolConfig("admin", "30"))
	ctx := checks.Context{Context: context.Background()}

	result := checkPoolUser{cache: &discoveryCache{}}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82/www:user=admin") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	writeFile(t, paths.poolConf, strings.Join([]string{
		"[www]",
		"user = root",
		"pm.max_children = 30",
	}, "\n"))
	result = checkPoolUser{cache: &discoveryCache{}}.Run(ctx)
	if result.Status != checks.StatusFail {
		t.Fatalf("expected fail status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82/www:user=root") {
		t.Fatalf("unexpected fail evidence: %s", result.Evidence)
	}
}

func TestPMMaxChildrenCheckPassAndWarn(t *testing.T) {
	paths := withPHPFPMFixture(t, goodPHPINI(), goodPoolConfig("admin", "80"))
	ctx := checks.Context{Context: context.Background()}

	result := checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82/www:pm.max_children=80") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	writeFile(t, paths.poolConf, goodPoolConfig("admin", "900"))
	result = checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status for high pm.max_children, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82/www:pm.max_children=900") {
		t.Fatalf("unexpected high evidence: %s", result.Evidence)
	}

	writeFile(t, paths.poolConf, strings.Join([]string{
		"[www]",
		"user = admin",
	}, "\n"))
	result = checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status for missing pm.max_children, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "php82/www:pm.max_children=empty") {
		t.Fatalf("unexpected missing evidence: %s", result.Evidence)
	}
}

func TestPoolParserKeepsPoolsWithMissingValues(t *testing.T) {
	pools := parsePoolConfig("php82", "/tmp/www.conf", strings.Join([]string{
		"[www]",
		"user = admin",
		"[legacy]",
		"pm.max_children = 25",
	}, "\n"))

	if len(pools) != 2 {
		t.Fatalf("expected two pools, got %d", len(pools))
	}
	if pools[0].Pool != "www" || pools[0].User != "admin" || pools[0].PMMaxChildren != "" {
		t.Fatalf("unexpected first pool: %#v", pools[0])
	}
	if pools[1].Pool != "legacy" || pools[1].User != "" || pools[1].PMMaxChildren != "25" {
		t.Fatalf("unexpected second pool: %#v", pools[1])
	}
}

func TestChecksNotApplicableWithoutPHPINIOrPools(t *testing.T) {
	paths := withPHPFPMFixture(t, goodPHPINI(), goodPoolConfig("admin", "30"))
	if err := os.Remove(paths.ini); err != nil {
		t.Fatalf("remove php.ini fixture: %v", err)
	}
	if err := os.Remove(paths.poolConf); err != nil {
		t.Fatalf("remove pool fixture: %v", err)
	}

	for _, check := range []checks.Check{
		checkExposePHP{cache: &discoveryCache{}},
		checkPoolUser{cache: &discoveryCache{}},
	} {
		result := check.Run(checks.Context{})
		if result.Status != checks.StatusNotApplicable {
			t.Fatalf("%s expected not_applicable, got %s", result.ID, result.Status)
		}
		assertCompleteResult(t, result)
	}
}

func withPHPFPMFixture(t *testing.T, phpINI, poolConfig string) fixturePaths {
	t.Helper()

	root := filepath.Join(t.TempDir(), "usr", "local", "php82")
	binary := filepath.Join(root, "sbin", "php-fpm")
	ini := filepath.Join(root, "lib", "php.ini")
	poolDir := filepath.Join(root, "etc", "php-fpm.d")
	poolConf := filepath.Join(poolDir, "www.conf")
	for _, dir := range []string{filepath.Dir(binary), filepath.Dir(ini), poolDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("create fixture dir %s: %v", dir, err)
		}
	}
	writeFile(t, binary, "#!/bin/sh\n")
	writeFile(t, ini, phpINI)
	writeFile(t, poolConf, poolConfig)

	originalBinaryGlobs := phpFPMBinaryGlobs
	originalDetectPaths := phpFPMDetectPaths
	originalDetectGlobs := phpFPMDetectGlobs
	phpFPMBinaryGlobs = []string{filepath.Join(filepath.Dir(root), "php*", "sbin", "php-fpm")}
	phpFPMDetectPaths = []string{binary}
	phpFPMDetectGlobs = []string{filepath.Join(root, "etc", "php-fpm.d", "*.conf")}
	t.Cleanup(func() {
		phpFPMBinaryGlobs = originalBinaryGlobs
		phpFPMDetectPaths = originalDetectPaths
		phpFPMDetectGlobs = originalDetectGlobs
	})

	return fixturePaths{
		root:     root,
		binary:   binary,
		ini:      ini,
		poolConf: poolConf,
	}
}

func goodPHPINI() string {
	return strings.Join([]string{
		"expose_php = Off",
		"display_errors = Off",
		"disable_functions = exec,passthru,shell_exec,system,proc_open,popen",
		"cgi.fix_pathinfo = 0",
	}, "\n")
}

func goodPoolConfig(user, maxChildren string) string {
	return strings.Join([]string{
		"[www]",
		"user = " + user,
		"pm = dynamic",
		"pm.max_children = " + maxChildren,
	}, "\n")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
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
