package phpfpm

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
}

func (r mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

type phpFixture struct {
	root       string
	directINI  string
	directPool string
	userPool   string
	systemINI  string
	systemPool string
	memInfo    string
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

func TestAvailableVersionsDirectAdminSystemAndMixed(t *testing.T) {
	fixture := withPHPFixture(t, "mixed")
	ctx := checks.Context{
		Context: context.Background(),
		Runner: mockRunner{outputs: map[string]string{
			"php -v":     "PHP 8.2.20 (cli) (built: test)\n",
			"php-fpm -v": "PHP 8.2.20 (fpm-fcgi) (built: test)\n",
		}},
	}

	result := checkAvailableVersions{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info, got %s", result.Status)
	}
	for _, needle := range []string{
		"version=8.3 sapi=fpm source_type=directadmin",
		"version=8.2 sapi=fpm source_type=system",
		"source_path=php -v",
		fixture.directPool,
	} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %s", needle, result.Evidence)
		}
	}
}

func TestAvailableVersionsDirectAdminOnly(t *testing.T) {
	withPHPFixture(t, "directadmin")
	result := checkAvailableVersions{cache: &discoveryCache{}}.Run(checks.Context{})
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "source_type=directadmin") || strings.Contains(result.Evidence, "source_type=system") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestAvailableVersionsSystemOnly(t *testing.T) {
	withPHPFixture(t, "system")
	result := checkAvailableVersions{cache: &discoveryCache{}}.Run(checks.Context{})
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "source_type=system") || strings.Contains(result.Evidence, "source_type=directadmin") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestPMMaxChildrenConfiguredMissingAndHigh(t *testing.T) {
	fixture := withPHPFixture(t, "directadmin")
	ctx := checks.Context{Context: context.Background()}

	result := checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "pm.max_children=40") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}

	writeFile(t, fixture.directPool, strings.Join([]string{
		"[www]",
		"user = admin",
	}, "\n"))
	result = checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "pm.max_children=empty") {
		t.Fatalf("expected missing warning, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.directPool, strings.Join([]string{
		"[www]",
		"user = admin",
		"pm.max_children = 250",
	}, "\n"))
	writeFile(t, fixture.memInfo, "MemTotal:        1048576 kB\n")
	result = checkPMMaxChildren{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "pm.max_children=250") {
		t.Fatalf("expected high warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestDisabledFunctionsEmptyAndPopulated(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkDisabledFunctions{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || !strings.Contains(result.Evidence, "disable_functions=count=3") {
		t.Fatalf("expected populated pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemINI, strings.Join([]string{
		"expose_php = Off",
		"display_errors = Off",
		"disable_functions =",
	}, "\n"))
	result = checkDisabledFunctions{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "count=0") {
		t.Fatalf("expected empty warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestOpenBasedirSetAndMissing(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkOpenBasedir{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || !strings.Contains(result.Evidence, "open_basedir=set") {
		t.Fatalf("expected open_basedir pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemINI, strings.Join([]string{
		"expose_php = Off",
		"display_errors = Off",
		"disable_functions = exec",
	}, "\n"))
	writeFile(t, fixture.systemPool, strings.Join([]string{
		"[www]",
		"user = www-data",
		"pm.max_children = 20",
	}, "\n"))
	result = checkOpenBasedir{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Evidence != "open_basedir=not_set" {
		t.Fatalf("expected open_basedir warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestLogsConfiguredWarnsForDevNullAndParsesAccessAndMail(t *testing.T) {
	fixture := withPHPFixture(t, "directadmin")
	writeFile(t, fixture.directINI, strings.Join([]string{
		"expose_php = Off",
		"display_errors = Off",
		"disable_functions = exec",
		"error_log = /dev/null",
	}, "\n"))

	result := checkLogsConfigured{cache: &discoveryCache{}}.Run(checks.Context{Context: context.Background()})
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s", result.Status)
	}
	for _, needle := range []string{"error_log=/dev/null", "access.log=/var/log/php-fpm/access.log", "/home/admin/.php/php-mail.log"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %s", needle, result.Evidence)
		}
	}
}

func TestSessionCookieSecurity(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkSessionCookieSecurity{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemINI, strings.Join([]string{
		"session.cookie_secure = 0",
		"session.cookie_httponly = Off",
	}, "\n"))
	result = checkSessionCookieSecurity{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "samesite=not_set") {
		t.Fatalf("expected session warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestExposePHPOnOff(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkExposePHP{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemINI, "expose_php = On\n")
	result = checkExposePHP{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "expose_php=On") {
		t.Fatalf("expected expose_php warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestDisplayErrorsOnOff(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkDisplayErrors{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemINI, "display_errors = On\n")
	result = checkDisplayErrors{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "display_errors=On") {
		t.Fatalf("expected display_errors warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestPoolUserRootPoolAndNormalUser(t *testing.T) {
	fixture := withPHPFixture(t, "directadmin")
	ctx := checks.Context{Context: context.Background()}

	result := checkPoolUser{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || !strings.Contains(result.Evidence, "user=$pool") {
		t.Fatalf("expected pass with $pool user, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.directPool, strings.Join([]string{
		"[www]",
		"user = root",
		"group = root",
		"pm.max_children = 20",
	}, "\n"))
	result = checkPoolUser{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusFail || !strings.Contains(result.Evidence, "user=root") {
		t.Fatalf("expected root failure, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestPoolSocketSecurityTmpAndSecurePath(t *testing.T) {
	fixture := withPHPFixture(t, "system")
	ctx := checks.Context{Context: context.Background()}

	result := checkPoolSocketSecurity{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", result.Status, result.Evidence)
	}

	writeFile(t, fixture.systemPool, strings.Join([]string{
		"[www]",
		"user = www-data",
		"listen = /tmp/php.sock",
		"listen.mode = 0666",
		"pm.max_children = 20",
	}, "\n"))
	result = checkPoolSocketSecurity{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || !strings.Contains(result.Evidence, "listen=/tmp/php.sock") {
		t.Fatalf("expected socket warning, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestChecksNotApplicableWithoutPHP(t *testing.T) {
	withPHPFixture(t, "none")
	ctx := checks.Context{Context: context.Background()}

	result := checkPoolUser{cache: &discoveryCache{}}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", result.Status)
	}
}

func withPHPFixture(t *testing.T, mode string) phpFixture {
	t.Helper()

	root := t.TempDir()
	fixture := phpFixture{
		root:       root,
		directINI:  filepath.Join(root, "usr", "local", "php83", "lib", "php.ini"),
		directPool: filepath.Join(root, "usr", "local", "php83", "etc", "php-fpm.d", "www.conf"),
		userPool:   filepath.Join(root, "usr", "local", "directadmin", "data", "users", "user", "php", "domusspolka.conf"),
		systemINI:  filepath.Join(root, "etc", "php", "8.2", "fpm", "php.ini"),
		systemPool: filepath.Join(root, "etc", "php", "8.2", "fpm", "pool.d", "www.conf"),
		memInfo:    filepath.Join(root, "proc", "meminfo"),
	}

	if mode == "directadmin" || mode == "mixed" {
		copyFixture(t, "fixtures/directadmin/php83/php.ini", fixture.directINI)
		copyFixture(t, "fixtures/directadmin/php83/pool.conf", fixture.directPool)
		copyFixture(t, "fixtures/directadmin-user-pool/domusspolka.conf", fixture.userPool)
		writeFile(t, filepath.Join(root, "usr", "local", "php83", "bin", "php"), "#!/bin/sh\n")
		writeFile(t, filepath.Join(root, "usr", "local", "php83", "sbin", "php-fpm"), "#!/bin/sh\n")
	}
	if mode == "system" || mode == "mixed" {
		copyFixture(t, "fixtures/system-php/8.2/php.ini", fixture.systemINI)
		copyFixture(t, "fixtures/system-php/8.2/www.conf", fixture.systemPool)
		writeFile(t, filepath.Join(root, "usr", "bin", "php8.2"), "#!/bin/sh\n")
		writeFile(t, filepath.Join(root, "usr", "sbin", "php-fpm8.2"), "#!/bin/sh\n")
	}
	writeFile(t, fixture.memInfo, "MemTotal:        8388608 kB\n")

	originalDirectPHP := directAdminPHPBinaryGlobs
	originalDirectFPM := directAdminFPMBinaryGlobs
	originalDirectINI := directAdminINIGlobs
	originalDirectPools := directAdminPoolGlobs
	originalSystemPHP := systemPHPBinaryGlobs
	originalSystemFPM := systemFPMBinaryGlobs
	originalSystemFPMINI := systemFPMINIGlobs
	originalSystemCLIINI := systemCLIINIGlobs
	originalSystemPools := systemPoolGlobs
	originalMemInfo := memInfoPath

	directAdminPHPBinaryGlobs = []string{filepath.Join(root, "usr", "local", "php*", "bin", "php")}
	directAdminFPMBinaryGlobs = []string{filepath.Join(root, "usr", "local", "php*", "sbin", "php-fpm")}
	directAdminINIGlobs = []string{filepath.Join(root, "usr", "local", "php*", "lib", "php.ini")}
	directAdminPoolGlobs = []string{
		filepath.Join(root, "usr", "local", "php*", "etc", "php-fpm.conf"),
		filepath.Join(root, "usr", "local", "php*", "etc", "php-fpm.d", "*.conf"),
		filepath.Join(root, "usr", "local", "directadmin", "data", "users", "*", "php", "*"),
	}
	systemPHPBinaryGlobs = []string{filepath.Join(root, "usr", "bin", "php*")}
	systemFPMBinaryGlobs = []string{filepath.Join(root, "usr", "sbin", "php-fpm*")}
	systemFPMINIGlobs = []string{filepath.Join(root, "etc", "php", "*", "fpm", "php.ini")}
	systemCLIINIGlobs = []string{filepath.Join(root, "etc", "php", "*", "cli", "php.ini")}
	systemPoolGlobs = []string{filepath.Join(root, "etc", "php", "*", "fpm", "pool.d", "*.conf")}
	memInfoPath = fixture.memInfo

	t.Cleanup(func() {
		directAdminPHPBinaryGlobs = originalDirectPHP
		directAdminFPMBinaryGlobs = originalDirectFPM
		directAdminINIGlobs = originalDirectINI
		directAdminPoolGlobs = originalDirectPools
		systemPHPBinaryGlobs = originalSystemPHP
		systemFPMBinaryGlobs = originalSystemFPM
		systemFPMINIGlobs = originalSystemFPMINI
		systemCLIINIGlobs = originalSystemCLIINI
		systemPoolGlobs = originalSystemPools
		memInfoPath = originalMemInfo
	})

	return fixture
}

func copyFixture(t *testing.T, source, target string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read fixture %s: %v", source, err)
	}
	writeFile(t, target, string(data))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create fixture dir %s: %v", filepath.Dir(path), err)
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
