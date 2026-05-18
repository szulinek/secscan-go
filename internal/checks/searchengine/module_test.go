package searchengine

import (
	"context"
	"fmt"
	"os"
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

type searchFixture struct {
	root      string
	esConfig  string
	osConfig  string
	esShare   string
	osShare   string
	esJVM     string
	osJVM     string
	esJVMDrop string
	osJVMDrop string
	meminfo   string
}

func TestDetectModule(t *testing.T) {
	paths := withSearchFixture(t)
	ctx := checks.Context{
		Context:  context.Background(),
		Host:     system.Info{GOOS: "linux"},
		Services: []system.Service{{Unit: "elasticsearch.service"}},
	}

	if detected, evidence := detect(ctx); !detected || evidence != "engine=elasticsearch; running_service=elasticsearch.service" {
		t.Fatalf("expected elasticsearch service detection, got %v %q", detected, evidence)
	}

	ctx.Services = []system.Service{{Unit: "opensearch.service"}}
	if detected, evidence := detect(ctx); !detected || evidence != "engine=opensearch; running_service=opensearch.service" {
		t.Fatalf("expected opensearch service detection, got %v %q", detected, evidence)
	}

	ctx.Services = nil
	ctx.Runner = &mockRunner{outputs: map[string]string{"pgrep -x opensearch": "123\n"}}
	if detected, evidence := detect(ctx); !detected || evidence != "engine=opensearch; process=opensearch" {
		t.Fatalf("expected process detection, got %v %q", detected, evidence)
	}

	ctx.Runner = nil
	copyFixture(t, "fixtures/elasticsearch_localhost_secure.yml", paths.esConfig)
	if detected, evidence := detect(ctx); !detected || evidence != "engine=elasticsearch; path_exists="+paths.esConfig {
		t.Fatalf("expected config path detection, got %v %q", detected, evidence)
	}
}

func TestVersionCheck(t *testing.T) {
	withSearchFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"elasticsearch --version": "Version: 8.12.2, Build: default/tar/abc/2024-02-01T00:00:00Z, JVM: 21\n",
	}}

	result := checkVersion{}.Run(searchContext(engineElasticsearch, runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo || result.Evidence != "engine=elasticsearch; version=8.12.2; source=elasticsearch" {
		t.Fatalf("unexpected version result: %s %s", result.Status, result.Evidence)
	}
}

func TestClusterHealthGreenYellowRed(t *testing.T) {
	withSearchFixture(t)
	for _, item := range []struct {
		fixture  string
		status   checks.Status
		severity checks.Severity
	}{
		{fixture: "fixtures/cluster_health_green.json", status: checks.StatusPass, severity: checks.SeverityHigh},
		{fixture: "fixtures/cluster_health_yellow.json", status: checks.StatusWarn, severity: checks.SeverityMedium},
		{fixture: "fixtures/cluster_health_red.json", status: checks.StatusFail, severity: checks.SeverityHigh},
	} {
		result := checkClusterHealth{}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
			"curl --max-time 2 -fsS http://127.0.0.1:9200/_cluster/health": readFixture(t, item.fixture),
		}}))
		assertCompleteResult(t, result)
		if result.Status != item.status || result.Severity != item.severity {
			t.Fatalf("%s expected %s/%s, got %s/%s", item.fixture, item.status, item.severity, result.Status, result.Severity)
		}
	}
}

func TestBindLocalhostPassAndPublicWarn(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_localhost_secure.yml", paths.esConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	pass := checkBindLocalhost{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"ss -tulpn": `tcp LISTEN 0 4096 127.0.0.1:9200 0.0.0.0:* users:(("elasticsearch",pid=123,fd=1))`,
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	copyFixture(t, "fixtures/elasticsearch_public_insecure.yml", paths.esConfig)
	warn := checkBindLocalhost{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/ss_public_9200.txt"),
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s (%s)", warn.Status, warn.Severity, warn.Evidence)
	}
}

func TestJVMMemoryOKMismatchAndTooLarge(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_localhost_secure.yml", paths.esConfig)
	writeFile(t, paths.meminfo, "MemTotal:        8388608 kB\n")

	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	pass := checkJVMMemory{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected JVM pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	copyFixture(t, "fixtures/jvm_mismatch.options", paths.esJVM)
	mismatch := checkJVMMemory{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, mismatch)
	if mismatch.Status != checks.StatusWarn {
		t.Fatalf("expected JVM mismatch warn, got %s (%s)", mismatch.Status, mismatch.Evidence)
	}

	writeFile(t, paths.esJVM, "-Xms6g\n-Xmx6g\n")
	tooLarge := checkJVMMemory{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, tooLarge)
	if tooLarge.Status != checks.StatusWarn {
		t.Fatalf("expected JVM too large warn, got %s (%s)", tooLarge.Status, tooLarge.Evidence)
	}
}

func TestOpenSearchSecurityDisabledPublicHigh(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/opensearch_security_disabled.yml", paths.osConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.osJVM)
	result := checkSecurityEnabled{cache: &discoveryCache{}}.Run(searchContext(engineOpenSearch, &mockRunner{outputs: map[string]string{
		"ss -tulpn": `tcp LISTEN 0 4096 0.0.0.0:9200 0.0.0.0:* users:(("opensearch",pid=123,fd=1))`,
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high security warning, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "engine=opensearch; security=disabled; public_bind=true") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestRunsAsRootDetection(t *testing.T) {
	withSearchFixture(t)
	root := checkRunsAsRoot{}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"systemctl show elasticsearch.service -p User --value": "root\n",
	}}))
	assertCompleteResult(t, root)
	if root.Status != checks.StatusFail || root.Severity != checks.SeverityHigh {
		t.Fatalf("expected root fail, got %s/%s (%s)", root.Status, root.Severity, root.Evidence)
	}

	pass := checkRunsAsRoot{}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"systemctl show elasticsearch.service -p User --value": "elasticsearch\n",
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected non-root pass, got %s (%s)", pass.Status, pass.Evidence)
	}
}

func TestSnapshotRepoDetection(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_localhost_secure.yml", paths.esConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	result := checkBackupsSnapshots{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"ss -tulpn": "",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || !strings.Contains(result.Evidence, "path.repo=/var/backups/elasticsearch") {
		t.Fatalf("expected snapshot path pass, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestTLSPublicWarn(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_public_insecure.yml", paths.esConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	result := checkTLSConfigured{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/ss_public_9200.txt"),
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high TLS warning, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
}

func TestDangerousDestructiveActions(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_public_insecure.yml", paths.esConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	result := checkDangerousDestructiveActions{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Evidence != "value=false" {
		t.Fatalf("expected destructive action warning, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, paths.esConfig, "network.host: 127.0.0.1\n")
	missing := checkDangerousDestructiveActions{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, missing)
	if missing.Status != checks.StatusWarn || missing.Evidence != "value=not_set" {
		t.Fatalf("expected missing destructive action warning, got %s (%s)", missing.Status, missing.Evidence)
	}
}

func TestFilePermissionsWorldWritable(t *testing.T) {
	paths := withSearchFixture(t)
	copyFixture(t, "fixtures/elasticsearch_localhost_secure.yml", paths.esConfig)
	copyFixture(t, "fixtures/jvm_ok.options", paths.esJVM)
	if err := os.Chmod(paths.esConfig, 0666); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}

	result := checkFilePermissions{cache: &discoveryCache{}}.Run(searchContext(engineElasticsearch, &mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusFail || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected world-writable fail, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
}

func searchContext(engine string, runner *mockRunner) checks.Context {
	unit := "elasticsearch.service"
	if engine == engineOpenSearch {
		unit = "opensearch.service"
	}
	return checks.Context{
		Context:  context.Background(),
		Runner:   runner,
		Host:     system.Info{GOOS: "linux"},
		Services: []system.Service{{Unit: unit}},
	}
}

func withSearchFixture(t *testing.T) searchFixture {
	t.Helper()

	root := t.TempDir()
	paths := searchFixture{
		root:      root,
		esConfig:  filepath.Join(root, "etc", "elasticsearch", "elasticsearch.yml"),
		osConfig:  filepath.Join(root, "etc", "opensearch", "opensearch.yml"),
		esShare:   filepath.Join(root, "usr", "share", "elasticsearch"),
		osShare:   filepath.Join(root, "usr", "share", "opensearch"),
		esJVM:     filepath.Join(root, "etc", "elasticsearch", "jvm.options"),
		osJVM:     filepath.Join(root, "etc", "opensearch", "jvm.options"),
		esJVMDrop: filepath.Join(root, "etc", "elasticsearch", "jvm.options.d", "*.options"),
		osJVMDrop: filepath.Join(root, "etc", "opensearch", "jvm.options.d", "*.options"),
		meminfo:   filepath.Join(root, "proc", "meminfo"),
	}
	if err := os.MkdirAll(paths.esShare, 0755); err != nil {
		t.Fatalf("create es share: %v", err)
	}
	if err := os.MkdirAll(paths.osShare, 0755); err != nil {
		t.Fatalf("create os share: %v", err)
	}
	writeFile(t, paths.meminfo, "MemTotal:        8388608 kB\n")

	originalESConfig := elasticsearchConfigPaths
	originalOSConfig := opensearchConfigPaths
	originalESShare := elasticsearchSharePaths
	originalOSShare := opensearchSharePaths
	originalESJVM := elasticsearchJVMPatterns
	originalOSJVM := opensearchJVMPatterns
	originalMeminfo := memInfoPath
	elasticsearchConfigPaths = []string{paths.esConfig}
	opensearchConfigPaths = []string{paths.osConfig}
	elasticsearchSharePaths = []string{paths.esShare}
	opensearchSharePaths = []string{paths.osShare}
	elasticsearchJVMPatterns = []string{paths.esJVM, paths.esJVMDrop}
	opensearchJVMPatterns = []string{paths.osJVM, paths.osJVMDrop}
	memInfoPath = paths.meminfo

	t.Cleanup(func() {
		elasticsearchConfigPaths = originalESConfig
		opensearchConfigPaths = originalOSConfig
		elasticsearchSharePaths = originalESShare
		opensearchSharePaths = originalOSShare
		elasticsearchJVMPatterns = originalESJVM
		opensearchJVMPatterns = originalOSJVM
		memInfoPath = originalMeminfo
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
