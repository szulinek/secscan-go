package varnish

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type mockRunner struct {
	outputs map[string]string
	errors  map[string]error
	counts  map[string]int
}

func (r *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[key]++
	if err, ok := r.errors[key]; ok {
		return nil, err
	}
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

type varnishFixture struct {
	root          string
	varnishd      string
	varnishstat   string
	defaultVCL    string
	defaultConfig string
	params        string
}

func TestDetectModule(t *testing.T) {
	paths := withVarnishFixture(t)
	ctx := checks.Context{
		Context:  context.Background(),
		Services: []system.Service{{Unit: "varnish.service"}},
	}

	if detected, evidence := detect(ctx); !detected || evidence != "running_service=varnish.service" {
		t.Fatalf("expected service detection, got %v %q", detected, evidence)
	}

	ctx.Services = nil
	if detected, evidence := detect(ctx); !detected || evidence != "binary="+paths.varnishd {
		t.Fatalf("expected varnishd binary detection, got %v %q", detected, evidence)
	}

	if err := os.Remove(paths.varnishd); err != nil {
		t.Fatalf("remove varnishd: %v", err)
	}
	if detected, evidence := detect(ctx); !detected || evidence != "binary="+paths.varnishstat {
		t.Fatalf("expected varnishstat binary detection, got %v %q", detected, evidence)
	}

	if err := os.Remove(paths.varnishstat); err != nil {
		t.Fatalf("remove varnishstat: %v", err)
	}
	if detected, evidence := detect(ctx); !detected || evidence != "path_exists="+paths.defaultVCL {
		t.Fatalf("expected default.vcl detection, got %v %q", detected, evidence)
	}
}

func TestVersionCheck(t *testing.T) {
	withVarnishFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"varnishd -V": "varnishd (varnish-7.4.2 revision abcdef)\n",
	}}

	result := checkVersion{}.Run(varnishContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
	if result.Evidence != "version=7.4.2" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestVersionCommandError(t *testing.T) {
	withVarnishFixture(t)
	runner := &mockRunner{errors: map[string]error{
		"varnishd -V": fmt.Errorf("varnishd failed"),
	}}

	result := checkVersion{}.Run(varnishContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestStorageMallocFromSystemdAndDefaultParams(t *testing.T) {
	paths := withVarnishFixture(t)
	copyFixture(t, "fixtures/default_malloc", paths.defaultConfig)
	writeFile(t, paths.params, `VARNISH_STORAGE="-s malloc,1G"`)
	runner := &mockRunner{outputs: map[string]string{
		"systemctl show varnish.service -p ExecStart --value": "/usr/sbin/varnishd -a :6081 -s malloc,256m",
	}}

	result := checkStorageMalloc{}.Run(varnishContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "storage=malloc,size=256m") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestStorageFileWarns(t *testing.T) {
	paths := withVarnishFixture(t)
	copyFixture(t, "fixtures/default_file", paths.defaultConfig)
	runner := &mockRunner{errors: map[string]error{
		"systemctl show varnish.service -p ExecStart --value": fmt.Errorf("systemctl unavailable"),
	}}

	result := checkStorageMalloc{}.Run(varnishContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "storage=file") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestCacheHitRatioHealthyAndLow(t *testing.T) {
	withVarnishFixture(t)
	healthy := checkCacheHitRatio{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": readFixture(t, "fixtures/varnishstat_healthy.txt"),
	}}))
	assertCompleteResult(t, healthy)
	if healthy.Status != checks.StatusPass || !strings.Contains(healthy.Evidence, "ratio=0.78") {
		t.Fatalf("expected healthy pass, got %s (%s)", healthy.Status, healthy.Evidence)
	}

	low := checkCacheHitRatio{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": readFixture(t, "fixtures/varnishstat_low_hit_ratio.txt"),
	}}))
	assertCompleteResult(t, low)
	if low.Status != checks.StatusWarn || low.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium warn, got %s/%s", low.Status, low.Severity)
	}
	if !strings.Contains(low.Evidence, "ratio=0.20") {
		t.Fatalf("unexpected evidence: %s", low.Evidence)
	}
}

func TestCacheHitRatioNoDataIsInfo(t *testing.T) {
	withVarnishFixture(t)
	result := checkCacheHitRatio{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": "MAIN.cache_hit 0\nMAIN.cache_miss 0\n",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
}

func TestLRUNukedObjects(t *testing.T) {
	withVarnishFixture(t)
	pass := checkLRUNukedObjects{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": readFixture(t, "fixtures/varnishstat_healthy.txt"),
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s", pass.Status)
	}

	warn := checkLRUNukedObjects{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": readFixture(t, "fixtures/varnishstat_lru_nuked.txt"),
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", warn.Status, warn.Severity)
	}
	if warn.Evidence != "lru_nuked=1201" {
		t.Fatalf("unexpected evidence: %s", warn.Evidence)
	}
}

func TestBackendHealthWarnAndNotApplicable(t *testing.T) {
	withVarnishFixture(t)
	warn := checkBackendHealth{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": "VBE.boot.default.happy 0\n",
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s", warn.Status)
	}

	na := checkBackendHealth{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"varnishstat -1": "MAIN.cache_hit 1\n",
	}}))
	assertCompleteResult(t, na)
	if na.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", na.Status)
	}
}

func TestPublicAdminPort6082Warns(t *testing.T) {
	withVarnishFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"ss -tulpn": strings.Join([]string{
			"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
			"tcp LISTEN 0 128 0.0.0.0:6082 0.0.0.0:* users:((\"varnishd\",pid=123,fd=8))",
			"tcp LISTEN 0 128 127.0.0.1:6081 0.0.0.0:* users:((\"varnishd\",pid=123,fd=9))",
		}, "\n"),
	}}

	result := checkListenPorts{}.Run(varnishContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "0.0.0.0:6082") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestListenPortsInfo(t *testing.T) {
	withVarnishFixture(t)
	result := checkListenPorts{}.Run(varnishContext(&mockRunner{outputs: map[string]string{
		"ss -tulpn": `tcp LISTEN 0 128 127.0.0.1:6081 0.0.0.0:* users:(("varnishd",pid=123,fd=9))`,
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "127.0.0.1:6081") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func varnishContext(runner *mockRunner) checks.Context {
	return checks.Context{
		Context:  context.Background(),
		Runner:   runner,
		Services: []system.Service{{Unit: "varnish.service"}},
	}
}

func withVarnishFixture(t *testing.T) varnishFixture {
	t.Helper()

	root := t.TempDir()
	paths := varnishFixture{
		root:          root,
		varnishd:      filepath.Join(root, "usr", "sbin", "varnishd"),
		varnishstat:   filepath.Join(root, "usr", "bin", "varnishstat"),
		defaultVCL:    filepath.Join(root, "etc", "varnish", "default.vcl"),
		defaultConfig: filepath.Join(root, "etc", "default", "varnish"),
		params:        filepath.Join(root, "etc", "varnish", "varnish.params"),
	}
	writeFile(t, paths.varnishd, "#!/bin/sh\n")
	writeFile(t, paths.varnishstat, "#!/bin/sh\n")
	writeFile(t, paths.defaultVCL, "vcl 4.1;\n")

	originalDefaultVCL := varnishDefaultVCLPath
	originalDefaultConfig := varnishDefaultConfigPath
	originalParams := varnishParamsPath
	originalVarnishd := varnishdBinaryPaths
	originalVarnishstat := varnishstatBinaryPaths
	originalLookPath := lookPath
	varnishDefaultVCLPath = paths.defaultVCL
	varnishDefaultConfigPath = paths.defaultConfig
	varnishParamsPath = paths.params
	varnishdBinaryPaths = []string{paths.varnishd}
	varnishstatBinaryPaths = []string{paths.varnishstat}
	lookPath = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}

	t.Cleanup(func() {
		varnishDefaultVCLPath = originalDefaultVCL
		varnishDefaultConfigPath = originalDefaultConfig
		varnishParamsPath = originalParams
		varnishdBinaryPaths = originalVarnishd
		varnishstatBinaryPaths = originalVarnishstat
		lookPath = originalLookPath
	})

	return paths
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create parent for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func copyFixture(t *testing.T, source, target string) {
	t.Helper()
	writeFile(t, target, readFixture(t, source))
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
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
	if result.Status == checks.StatusWarn || result.Status == checks.StatusFail {
		if len(result.RemediationSteps) == 0 {
			missing = append(missing, "remediation_steps")
		}
		if result.Automation.Shell == "" {
			missing = append(missing, "automation.shell")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%s missing fields: %s", result.ID, strings.Join(missing, ", "))
	}
}
