package redis

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

type redisFixturePaths struct {
	root   string
	config string
	binary string
}

func TestVersionFromRedisServer(t *testing.T) {
	withRedisFixture(t, secureRedisConfig())
	runner := &mockRunner{outputs: map[string]string{
		"redis-server --version": "Redis server v=7.2.4 sha=00000000:0 malloc=libc bits=64 build=local\n",
	}}

	result := checkVersion{}.Run(redisContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "version=7.2.4") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestVersionFallbackToRedisCLIInfo(t *testing.T) {
	withRedisFixture(t, secureRedisConfig())
	runner := &mockRunner{
		outputs: map[string]string{
			"redis-cli INFO server": "# Server\r\nredis_version:7.0.15\r\n",
		},
		errors: map[string]error{
			"redis-server --version": fmt.Errorf("redis-server: executable file not found"),
		},
	}

	result := checkVersion{}.Run(redisContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "version=7.0.15") || !strings.Contains(result.Evidence, "source=redis-cli") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestVersionCommandError(t *testing.T) {
	withRedisFixture(t, secureRedisConfig())
	runner := &mockRunner{errors: map[string]error{
		"redis-server --version": fmt.Errorf("redis-server failed"),
		"redis-cli INFO server":  fmt.Errorf("NOAUTH Authentication required"),
	}}

	result := checkVersion{}.Run(redisContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "command_error=true") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestRedisChecksPass(t *testing.T) {
	withRedisFixture(t, secureRedisConfig())
	ctx := redisContext(&mockRunner{})

	for _, check := range []checks.Check{
		checkBindLocalhost{cache: &configCache{}},
		checkProtectedMode{cache: &configCache{}},
		checkMaxMemory{cache: &configCache{}},
		checkPersistence{cache: &configCache{}},
		checkAuthentication{cache: &configCache{}},
	} {
		result := check.Run(ctx)
		assertCompleteResult(t, result)
		if result.Status != checks.StatusPass {
			t.Fatalf("%s expected pass, got %s (%s)", result.ID, result.Status, result.Evidence)
		}
	}
}

func TestPublicBindWarnsHigh(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 0.0.0.0",
		"protected-mode yes",
		"maxmemory 512mb",
		"appendonly yes",
		"requirepass strong-secret",
	}, "\n"))

	result := checkBindLocalhost{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "bind=0.0.0.0") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestLocalhostBindPasses(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 127.0.0.1 localhost",
		"protected-mode yes",
		"maxmemory 256mb",
		"appendonly yes",
		"requirepass strong-secret",
	}, "\n"))

	result := checkBindLocalhost{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestProtectedModeOffWarns(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 127.0.0.1",
		"protected-mode no",
		"maxmemory 256mb",
		"appendonly yes",
		"requirepass strong-secret",
	}, "\n"))

	result := checkProtectedMode{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", result.Status, result.Severity)
	}
	if result.Evidence != "protected-mode=no" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestMaxMemoryUnsetWarns(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 127.0.0.1",
		"protected-mode yes",
		"maxmemory 0",
		"appendonly yes",
		"requirepass strong-secret",
	}, "\n"))

	result := checkMaxMemory{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium warn, got %s/%s", result.Status, result.Severity)
	}
	if result.Evidence != "maxmemory=0" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestPersistenceMissingWarns(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 127.0.0.1",
		"protected-mode yes",
		"maxmemory 256mb",
		`save ""`,
		"appendonly no",
		"requirepass strong-secret",
	}, "\n"))

	result := checkPersistence{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "appendonly=no") || !strings.Contains(result.Evidence, "save=none") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestAuthenticationMissingPublicBindIsCritical(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 0.0.0.0",
		"protected-mode yes",
		"maxmemory 256mb",
		"appendonly yes",
	}, "\n"))

	result := checkAuthentication{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityCritical {
		t.Fatalf("expected critical warn, got %s/%s", result.Status, result.Severity)
	}
	if result.Evidence != "requirepass=not_set; acl=disabled" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestAuthenticationPassesWithACLEnabled(t *testing.T) {
	withRedisFixture(t, strings.Join([]string{
		"bind 127.0.0.1",
		"protected-mode yes",
		"maxmemory 256mb",
		"appendonly yes",
		"user app on >strong-secret ~* +@all",
	}, "\n"))

	result := checkAuthentication{cache: &configCache{}}.Run(redisContext(&mockRunner{}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s", result.Status)
	}
	if result.Evidence != "requirepass=not_set; acl=enabled" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
	if strings.Contains(result.Evidence, "strong-secret") {
		t.Fatalf("evidence must not expose secrets: %s", result.Evidence)
	}
}

func TestConfigChecksNotApplicableWithoutRedis(t *testing.T) {
	withRedisFixture(t, secureRedisConfig())
	redisConfigPaths = []string{filepath.Join(t.TempDir(), "missing.conf")}
	redisBinaryPaths = []string{filepath.Join(t.TempDir(), "redis-server")}

	ctx := checks.Context{
		Context: context.Background(),
		Runner:  &mockRunner{errors: map[string]error{"pgrep -x redis-server": fmt.Errorf("not found")}},
		Host:    system.Info{GOOS: "linux"},
	}

	result := checkMaxMemory{cache: &configCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", result.Status)
	}
}

func TestDetectionUsesProcessServiceCLIAndConfig(t *testing.T) {
	paths := withRedisFixture(t, secureRedisConfig())
	ctx := checks.Context{Context: context.Background(), Host: system.Info{GOOS: "linux"}}

	ctx.Services = []system.Service{{Unit: "redis.service"}}
	if detected, evidence := detect(ctx); !detected || evidence != "running_service=redis.service" {
		t.Fatalf("expected service detection, got %v %q", detected, evidence)
	}

	ctx.Services = nil
	ctx.Runner = &mockRunner{outputs: map[string]string{"pgrep -x redis-server": "1234\n"}}
	if detected, evidence := detect(ctx); !detected || evidence != "process=redis-server" {
		t.Fatalf("expected process detection, got %v %q", detected, evidence)
	}

	redisConfigPaths = []string{filepath.Join(t.TempDir(), "missing.conf")}
	redisBinaryPaths = []string{filepath.Join(t.TempDir(), "missing-redis-server")}
	lookPath = func(name string) (string, error) {
		return "/usr/bin/redis-cli", nil
	}
	ctx.Runner = &mockRunner{errors: map[string]error{"pgrep -x redis-server": fmt.Errorf("not found")}}
	if detected, evidence := detect(ctx); !detected || evidence != "binary=/usr/bin/redis-cli" {
		t.Fatalf("expected redis-cli detection, got %v %q", detected, evidence)
	}

	lookPath = func(name string) (string, error) { return "", exec.ErrNotFound }
	redisConfigPaths = []string{paths.config}
	if detected, evidence := detect(ctx); !detected || !strings.Contains(evidence, "path_exists=") {
		t.Fatalf("expected config path detection, got %v %q", detected, evidence)
	}
}

func redisContext(runner *mockRunner) checks.Context {
	return checks.Context{
		Context: context.Background(),
		Runner:  runner,
		Host:    system.Info{GOOS: "linux"},
		Services: []system.Service{
			{Unit: "redis.service"},
		},
	}
}

func withRedisFixture(t *testing.T, config string) redisFixturePaths {
	t.Helper()

	root := t.TempDir()
	paths := redisFixturePaths{
		root:   root,
		config: filepath.Join(root, "etc", "redis", "redis.conf"),
		binary: filepath.Join(root, "usr", "bin", "redis-server"),
	}
	writeFile(t, paths.config, config)
	writeFile(t, paths.binary, "#!/bin/sh\n")

	originalConfigPaths := redisConfigPaths
	originalBinaryPaths := redisBinaryPaths
	originalLookPath := lookPath
	redisConfigPaths = []string{paths.config}
	redisBinaryPaths = []string{paths.binary}
	lookPath = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() {
		redisConfigPaths = originalConfigPaths
		redisBinaryPaths = originalBinaryPaths
		lookPath = originalLookPath
	})

	return paths
}

func secureRedisConfig() string {
	return strings.Join([]string{
		"bind 127.0.0.1 10.0.0.5",
		"protected-mode yes",
		"maxmemory 512mb",
		"save 900 1",
		"appendonly no",
		"requirepass strong-secret",
	}, "\n")
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
