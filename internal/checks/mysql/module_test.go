package mysql

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

type mysqlFixture struct {
	root         string
	socket       string
	binary       string
	daMyCNF      string
	daMysqlConf  string
	systemMyCNF  string
	mariadbCNF   string
	backupConf   string
	backupRoot   string
	meminfo      string
	worldConf    string
	emptyConfDir string
}

func TestDetectServiceSocketAndBinary(t *testing.T) {
	paths := withMySQLFixture(t)
	ctx := checks.Context{
		Context:  context.Background(),
		Services: []system.Service{{Unit: "mysqld.service"}},
	}
	detected, evidence := detect(ctx)
	if !detected || evidence != "running_service=mysqld.service" {
		t.Fatalf("expected service detection, got %v %q", detected, evidence)
	}

	ctx.Services = nil
	detected, evidence = detect(ctx)
	if !detected || evidence != "socket="+paths.socket {
		t.Fatalf("expected socket detection, got %v %q", detected, evidence)
	}

	if err := os.Remove(paths.socket); err != nil {
		t.Fatalf("remove socket: %v", err)
	}
	detected, evidence = detect(ctx)
	if !detected || evidence != "binary="+paths.binary {
		t.Fatalf("expected binary detection, got %v %q", detected, evidence)
	}
}

func TestDetectDirectAdminAndStandalonePaths(t *testing.T) {
	paths := withMySQLFixture(t)
	if err := os.Remove(paths.socket); err != nil {
		t.Fatalf("remove socket: %v", err)
	}
	if err := os.Remove(paths.binary); err != nil {
		t.Fatalf("remove binary: %v", err)
	}

	copyFixture(t, "fixtures/directadmin/my.cnf", paths.daMyCNF)
	ctx := checks.Context{Context: context.Background()}
	detected, evidence := detect(ctx)
	if !detected || evidence != "path_exists="+paths.daMyCNF {
		t.Fatalf("expected DirectAdmin path detection, got %v %q", detected, evidence)
	}

	if err := os.Remove(paths.daMyCNF); err != nil {
		t.Fatalf("remove DA config: %v", err)
	}
	copyFixture(t, "fixtures/system/my.cnf", paths.systemMyCNF)
	detected, evidence = detect(ctx)
	if !detected || evidence != "path_exists="+paths.systemMyCNF {
		t.Fatalf("expected standalone path detection, got %v %q", detected, evidence)
	}
}

func TestVersionCheckAndParser(t *testing.T) {
	withMySQLFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"mysqld --version": "/usr/sbin/mysqld  Ver 10.6.18-MariaDB for Linux on x86_64\n",
	}}

	result := checkVersion{}.Run(mysqlContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo || result.Evidence != "version=10.6.18-MariaDB; source=mysqld" {
		t.Fatalf("unexpected version result: %s %s", result.Status, result.Evidence)
	}
	if got := parseVersion("mysql  Ver 8.0.36 for Linux on x86_64"); got != "8.0.36" {
		t.Fatalf("parse version: got %q", got)
	}
}

func TestVersionError(t *testing.T) {
	withMySQLFixture(t)
	runner := &mockRunner{errors: map[string]error{
		"mysqld --version":   fmt.Errorf("no mysqld"),
		"mariadbd --version": fmt.Errorf("no mariadbd"),
		"mysql --version":    fmt.Errorf("no mysql"),
		"mysqladmin version": fmt.Errorf("no mysqladmin"),
	}}
	result := checkVersion{}.Run(mysqlContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestBindLocalhostPassAndPublicWarn(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/directadmin/my.cnf", paths.daMyCNF)
	pass := checkBindLocalhost{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/runtime/ss_mysql_local.txt"),
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	copyFixture(t, "fixtures/system/my.cnf", paths.systemMyCNF)
	warn := checkBindLocalhost{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/runtime/ss_mysql_public.txt"),
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s (%s)", warn.Status, warn.Severity, warn.Evidence)
	}
}

func TestRemoteUsersWarnAndPass(t *testing.T) {
	withMySQLFixture(t)
	warn := checkRemoteAccess{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"mysql --protocol=socket -NBe SELECT User, Host FROM mysql.user;": readFixture(t, "fixtures/runtime/mysql_user_remote.txt"),
		"ss -tulpn": "",
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || !strings.Contains(warn.Evidence, "remote_users=2") {
		t.Fatalf("expected remote user warning, got %s (%s)", warn.Status, warn.Evidence)
	}

	pass := checkRemoteAccess{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"mysql --protocol=socket -NBe SELECT User, Host FROM mysql.user;": readFixture(t, "fixtures/runtime/mysql_user_local.txt"),
		"ss -tulpn": "",
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s (%s)", pass.Status, pass.Evidence)
	}
}

func TestRemoteAccessPermissionErrorIsInfo(t *testing.T) {
	withMySQLFixture(t)
	result := checkRemoteAccess{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{
		outputs: map[string]string{"ss -tulpn": ""},
		errors: map[string]error{
			"mysql --protocol=socket -NBe SELECT User, Host FROM mysql.user;": fmt.Errorf("permission denied for table mysql.user"),
		},
	}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo || result.Evidence != "mysql.user=not_accessible" {
		t.Fatalf("expected mysql.user permission info, got %s (%s)", result.Status, result.Evidence)
	}
}

func TestRootPasswordFailPassAndUnknown(t *testing.T) {
	withMySQLFixture(t)
	fail := checkRootPassword{}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"mysql --protocol=socket -uroot -e SELECT 1": "1\n",
	}}))
	assertCompleteResult(t, fail)
	if fail.Status != checks.StatusFail || fail.Evidence != "root_empty_password=true" {
		t.Fatalf("expected root password fail, got %s (%s)", fail.Status, fail.Evidence)
	}

	pass := checkRootPassword{}.Run(mysqlContext(&mockRunner{errors: map[string]error{
		"mysql --protocol=socket -uroot -e SELECT 1": fmt.Errorf("ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)"),
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass || pass.Evidence != "root_empty_password=false" {
		t.Fatalf("expected root password pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	unknown := checkRootPassword{}.Run(mysqlContext(&mockRunner{errors: map[string]error{
		"mysql --protocol=socket -uroot -e SELECT 1": fmt.Errorf("Can't connect to local MySQL server through socket"),
	}}))
	assertCompleteResult(t, unknown)
	if unknown.Status != checks.StatusNotApplicable || unknown.Evidence != "root_empty_password=unknown" {
		t.Fatalf("expected root password unknown, got %s (%s)", unknown.Status, unknown.Evidence)
	}
}

func TestAnonymousUsersWarnAndPass(t *testing.T) {
	withMySQLFixture(t)
	warn := checkAnonymousUsers{}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"mysql --protocol=socket -NBe SELECT User, Host FROM mysql.user WHERE User='';": readFixture(t, "fixtures/runtime/mysql_user_anonymous.txt"),
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Evidence != "anonymous_users=2" {
		t.Fatalf("expected anonymous warning, got %s (%s)", warn.Status, warn.Evidence)
	}

	pass := checkAnonymousUsers{}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"mysql --protocol=socket -NBe SELECT User, Host FROM mysql.user WHERE User='';": "",
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected pass, got %s", pass.Status)
	}
}

func TestBufferPoolThresholds(t *testing.T) {
	paths := withMySQLFixture(t)
	writeFile(t, paths.meminfo, "MemTotal:        8388608 kB\n")
	copyFixture(t, "fixtures/directadmin/my.cnf", paths.daMyCNF)
	pass := checkInnoDBBufferPool{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected buffer pool pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	writeFile(t, paths.daMyCNF, "[mysqld]\ninnodb_buffer_pool_size=7G\n")
	high := checkInnoDBBufferPool{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, high)
	if high.Status != checks.StatusWarn || high.Severity != checks.SeverityMedium {
		t.Fatalf("expected high buffer warning, got %s/%s (%s)", high.Status, high.Severity, high.Evidence)
	}

	writeFile(t, paths.daMyCNF, "[mysqld]\ninnodb_buffer_pool_size=128M\n")
	low := checkInnoDBBufferPool{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, low)
	if low.Status != checks.StatusWarn || low.Severity != checks.SeverityLow {
		t.Fatalf("expected low buffer warning, got %s/%s (%s)", low.Status, low.Severity, low.Evidence)
	}
}

func TestMaxConnectionsThresholds(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/system/my.cnf", paths.systemMyCNF)
	warn := checkMaxConnections{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityMedium {
		t.Fatalf("expected max_connections warning, got %s/%s", warn.Status, warn.Severity)
	}

	copyFixture(t, "fixtures/directadmin/my.cnf", paths.daMyCNF)
	if err := os.Remove(paths.systemMyCNF); err != nil {
		t.Fatalf("remove system config: %v", err)
	}
	pass := checkMaxConnections{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected max_connections pass, got %s", pass.Status)
	}
}

func TestTLSPublicBindWarnAndPass(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/system/my.cnf", paths.systemMyCNF)
	off := readFixture(t, "fixtures/runtime/show_variables_tls_off.txt")
	warn := checkTLSEnabled{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/runtime/ss_mysql_public.txt"),
		"mysql --protocol=socket -NBe SHOW VARIABLES LIKE 'have_ssl';":                 off,
		"mysql --protocol=socket -NBe SHOW VARIABLES LIKE 'require_secure_transport';": off,
	}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityHigh {
		t.Fatalf("expected public TLS warning, got %s/%s (%s)", warn.Status, warn.Severity, warn.Evidence)
	}

	copyFixture(t, "fixtures/directadmin/my.cnf", paths.daMyCNF)
	if err := os.Remove(paths.systemMyCNF); err != nil {
		t.Fatalf("remove system config: %v", err)
	}
	on := readFixture(t, "fixtures/runtime/show_variables_tls_on.txt")
	pass := checkTLSEnabled{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{
		"ss -tulpn": readFixture(t, "fixtures/runtime/ss_mysql_local.txt"),
		"mysql --protocol=socket -NBe SHOW VARIABLES LIKE 'have_ssl';":                 on,
		"mysql --protocol=socket -NBe SHOW VARIABLES LIKE 'require_secure_transport';": on,
	}}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass {
		t.Fatalf("expected TLS pass, got %s (%s)", pass.Status, pass.Evidence)
	}
}

func TestLogsConfigured(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/system/my.cnf", paths.systemMyCNF)
	info := checkLogsConfigured{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, info)
	if info.Status != checks.StatusInfo {
		t.Fatalf("expected logging info for slow log off, got %s (%s)", info.Status, info.Evidence)
	}

	writeFile(t, paths.systemMyCNF, "[mysqld]\nslow_query_log=ON\n")
	warn := checkLogsConfigured{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn || warn.Severity != checks.SeverityMedium {
		t.Fatalf("expected missing error log warning, got %s/%s", warn.Status, warn.Severity)
	}
}

func TestBackupsDetectedAndMissing(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/directadmin/backup.conf", paths.backupConf)
	writeFile(t, filepath.Join(paths.backupRoot, "db.sql.gz"), "dump")
	pass := checkBackupsDetected{}.Run(mysqlContext(&mockRunner{}))
	assertCompleteResult(t, pass)
	if pass.Status != checks.StatusPass || !strings.Contains(pass.Evidence, "db.sql.gz") {
		t.Fatalf("expected backup detection pass, got %s (%s)", pass.Status, pass.Evidence)
	}

	if err := os.Remove(paths.backupConf); err != nil {
		t.Fatalf("remove backup conf: %v", err)
	}
	if err := os.Remove(filepath.Join(paths.backupRoot, "db.sql.gz")); err != nil {
		t.Fatalf("remove backup file: %v", err)
	}
	warn := checkBackupsDetected{}.Run(mysqlContext(&mockRunner{}))
	assertCompleteResult(t, warn)
	if warn.Status != checks.StatusWarn {
		t.Fatalf("expected missing backup warning, got %s (%s)", warn.Status, warn.Evidence)
	}
}

func TestConfigPermissionsWorldWritable(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/directadmin/my.cnf", paths.worldConf)
	if err := os.Chmod(paths.worldConf, 0666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	result := checkConfigPermissions{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusFail || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected world writable fail, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
}

func TestSkipNameResolve(t *testing.T) {
	paths := withMySQLFixture(t)
	copyFixture(t, "fixtures/system/mariadb.cnf", paths.mariadbCNF)
	result := checkSkipNameResolve{cache: &discoveryCache{}}.Run(mysqlContext(&mockRunner{outputs: map[string]string{"ss -tulpn": ""}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || result.Evidence != "skip_name_resolve=enabled" {
		t.Fatalf("expected skip-name-resolve pass, got %s (%s)", result.Status, result.Evidence)
	}
}

func mysqlContext(runner *mockRunner) checks.Context {
	return checks.Context{
		Context:  context.Background(),
		Runner:   runner,
		Services: []system.Service{{Unit: "mariadb.service"}},
	}
}

func withMySQLFixture(t *testing.T) mysqlFixture {
	t.Helper()
	root := t.TempDir()
	paths := mysqlFixture{
		root:         root,
		socket:       filepath.Join(root, "run", "mysqld", "mysqld.sock"),
		binary:       filepath.Join(root, "usr", "sbin", "mysqld"),
		daMyCNF:      filepath.Join(root, "usr", "local", "directadmin", "conf", "my.cnf"),
		daMysqlConf:  filepath.Join(root, "usr", "local", "directadmin", "conf", "mysql.conf"),
		systemMyCNF:  filepath.Join(root, "etc", "mysql", "my.cnf"),
		mariadbCNF:   filepath.Join(root, "etc", "mysql", "mariadb.conf.d", "50-server.cnf"),
		backupConf:   filepath.Join(root, "usr", "local", "directadmin", "data", "admin", "backup.conf"),
		backupRoot:   filepath.Join(root, "home", "admin", "admin_backups"),
		meminfo:      filepath.Join(root, "proc", "meminfo"),
		worldConf:    filepath.Join(root, "etc", "my.cnf"),
		emptyConfDir: filepath.Join(root, "empty"),
	}
	writeFile(t, paths.socket, "")
	writeFile(t, paths.binary, "#!/bin/sh\n")
	writeFile(t, paths.meminfo, "MemTotal:        2097152 kB\n")

	origSockets := mysqlSocketPaths
	origBinaries := mysqlBinaryPaths
	origConfigs := mysqlConfigPatterns
	origDetectConfigs := mysqlDetectConfigPaths
	origBackupConfigs := mysqlBackupConfigPatterns
	origBackupRoots := mysqlBackupRoots
	origMemInfo := memInfoPath
	origLookPath := lookPath

	mysqlSocketPaths = []string{paths.socket}
	mysqlBinaryPaths = []string{paths.binary}
	mysqlConfigPatterns = []string{paths.daMyCNF, paths.systemMyCNF, paths.mariadbCNF, paths.worldConf}
	mysqlDetectConfigPaths = []string{paths.daMyCNF, paths.systemMyCNF, paths.worldConf}
	mysqlBackupConfigPatterns = []string{paths.backupConf}
	mysqlBackupRoots = []string{paths.backupRoot}
	memInfoPath = paths.meminfo
	lookPath = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}

	t.Cleanup(func() {
		mysqlSocketPaths = origSockets
		mysqlBinaryPaths = origBinaries
		mysqlConfigPatterns = origConfigs
		mysqlDetectConfigPaths = origDetectConfigs
		mysqlBackupConfigPatterns = origBackupConfigs
		mysqlBackupRoots = origBackupRoots
		memInfoPath = origMemInfo
		lookPath = origLookPath
	})
	return paths
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
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
