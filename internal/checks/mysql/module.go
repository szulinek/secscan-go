package mysql

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"secscan/internal/checks"
)

const (
	moduleID = "mysql_mariadb"
	service  = "mysql/mariadb"
)

var (
	mysqlSocketPaths = []string{
		"/var/lib/mysql/mysql.sock",
		"/run/mysqld/mysqld.sock",
		"/tmp/mysql.sock",
	}
	mysqlBinaryPaths = []string{
		"/usr/sbin/mysqld",
		"/usr/sbin/mariadbd",
		"/usr/bin/mysql",
		"/usr/bin/mariadb",
		"/usr/local/mysql/bin/mysqld",
		"/usr/local/mysql/bin/mariadbd",
		"/usr/local/mysql/bin/mysql",
		"/usr/local/bin/mysql",
		"/usr/local/bin/mariadb",
	}
	mysqlConfigPatterns = []string{
		"/usr/local/directadmin/conf/mysql.conf",
		"/usr/local/directadmin/conf/my.cnf",
		"/usr/local/directadmin/conf/directadmin.conf",
		"/usr/local/directadmin/data/admin/mysql.conf",
		"/usr/local/directadmin/data/users/*/mysql.conf",
		"/etc/my.cnf",
		"/etc/my.cnf.d/*.cnf",
		"/etc/mysql/my.cnf",
		"/etc/mysql/mysql.conf.d/*.cnf",
		"/etc/mysql/mariadb.conf.d/*.cnf",
		"/etc/mysql/conf.d/*.cnf",
		"/usr/local/mysql/etc/my.cnf",
		"/var/lib/mysql/my.cnf",
	}
	mysqlDetectConfigPaths = []string{
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
		"/usr/local/directadmin/conf/mysql.conf",
		"/usr/local/directadmin/conf/my.cnf",
	}
	mysqlBackupConfigPatterns = []string{
		"/usr/local/directadmin/data/admin/backup.conf",
		"/usr/local/directadmin/data/admin/backup_crons.list",
		"/usr/local/directadmin/data/users/*/backup.conf",
	}
	mysqlBackupRoots = []string{
		"/home/admin/admin_backups",
		"/home/*/backups",
		"/backup",
		"/backups",
		"/var/backups",
	}
	memInfoPath = "/proc/meminfo"
	lookPath    = exec.LookPath
)

var serverSections = []string{"mysqld", "server", "mariadb"}

type Module struct{}

type discoveryCache struct {
	loaded bool
	state  discoveryState
}

type discoveryState struct {
	detected       bool
	detectEvidence string
	config         Config
	configErr      error
	listens        []listenEndpoint
	ssErr          error
}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "MySQL / MariaDB"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &discoveryCache{}
	return []checks.Check{
		checkVersion{},
		checkBindLocalhost{cache: cache},
		checkRemoteAccess{cache: cache},
		checkRootPassword{},
		checkAnonymousUsers{},
		checkInnoDBBufferPool{cache: cache},
		checkMaxConnections{cache: cache},
		checkTLSEnabled{cache: cache},
		checkLogsConfigured{cache: cache},
		checkBackupsDetected{},
		checkConfigPermissions{cache: cache},
		checkSkipNameResolve{cache: cache},
	}
}

type checkVersion struct{}

func (c checkVersion) ID() string { return "mysql.version" }
func (c checkVersion) Title() string {
	return "MySQL or MariaDB version"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "MySQL or MariaDB version was collected."
	result.ClientSummary = "Database version information was recorded."
	result.AdminDetails = "Collected version information from mysqld, mariadbd, mysql, or mysqladmin when available."
	result.Impact = "Version inventory helps prioritize database patching and lifecycle decisions."
	result.Recommendation = "Keep MySQL or MariaDB on a supported and patched release."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "mysqld --version; mariadbd --version; mysql --version; mysqladmin version"}
	result.HiddenInClientReport = true

	if !ensureDetected(ctx, &result, "version check") {
		return result
	}
	version, source, err := mysqlVersion(ctx)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "MySQL or MariaDB version could not be collected."
		result.ClientSummary = "Database version could not be verified."
		result.AdminDetails = "All version commands failed.\n" + err.Error()
		result.Evidence = "version=unknown; source=unavailable"
		result.Error = err.Error()
		return result
	}
	result.Evidence = "version=" + version + "; source=" + source
	return result
}

type checkBindLocalhost struct {
	cache *discoveryCache
}

func (c checkBindLocalhost) ID() string { return "mysql.bind_localhost" }
func (c checkBindLocalhost) Title() string {
	return "MySQL bind address is restricted"
}

func (c checkBindLocalhost) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "MySQL network binding is restricted to local or private access."
	result.ClientSummary = "Database network exposure is restricted."
	result.AdminDetails = "Checked bind-address, skip-networking, and listening ports from ss."
	result.Impact = "A database listener exposed on public interfaces can allow remote attack attempts and unauthorized access if credentials are weak."
	result.Recommendation = "Bind MySQL to localhost or a private interface, or use socket-only access where possible."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Set bind-address to 127.0.0.1 or a private application interface, or enable skip-networking for socket-only deployments.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^\\s*bind-address\\|^\\s*skip-networking\" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null; ss -tulpn | grep -E ':(3306|3307)\\b'",
		Ansible: ansibleLine("bind-address", "127.0.0.1"),
		Chef:    chefLine("bind-address", "127.0.0.1"),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "bind address check")
	if !ok {
		return result
	}
	bind := serverSetting(state.config, "bind-address", "bind_address")
	skip := serverFlag(state.config, "skip-networking")
	exposure := networkExposure(state.config, state.listens)
	result.Evidence = fmt.Sprintf("bind_address=%s; skip_networking=%t; listen=%s", valueOrNotSet(bind.Value), skip, listenEvidence(state.listens))

	if skip || exposure == exposureRestricted {
		return result
	}
	result.Title = "MySQL may listen on a public interface"
	result.Status = checks.StatusWarn
	if exposure == exposurePublic {
		result.Severity = checks.SeverityHigh
		result.Summary = "MySQL appears to listen on a public or wildcard interface."
		result.ClientSummary = "Database network exposure should be restricted."
		return result
	}
	result.Summary = "MySQL bind address is not explicit and listening state could not be confirmed."
	result.ClientSummary = "Database network exposure is unclear."
	return result
}

type checkRemoteAccess struct {
	cache *discoveryCache
}

func (c checkRemoteAccess) ID() string { return "mysql.remote_access" }
func (c checkRemoteAccess) Title() string {
	return "MySQL remote user access"
}

func (c checkRemoteAccess) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusInfo)
	result.Summary = "MySQL user host access was checked."
	result.ClientSummary = "Database remote access configuration was checked."
	result.AdminDetails = "Queried mysql.user for User and Host only; no password hashes or secrets are collected."
	result.Impact = "Accounts allowed from wildcard or public hosts increase the blast radius of exposed database ports."
	result.Recommendation = "Restrict database accounts to localhost, private addresses, or specific application hosts."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review mysql.user Host values for wildcard or public entries.",
		"Replace broad Host values with the narrowest application host or private network required.",
		"Test application connectivity before removing legacy grants during an approved maintenance window.",
	}
	result.Automation = checks.Automation{Shell: `mysql --protocol=socket -NBe "SELECT User, Host FROM mysql.user;"`}

	if !ensureDetected(ctx, &result, "remote access check") {
		return result
	}
	_, _ = c.cache.load(ctx)
	output, err := mysqlQuery(ctx, "SELECT User, Host FROM mysql.user;")
	if err != nil {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "mysql.user was not accessible; remote user grants could not be verified."
		result.ClientSummary = "Database remote user grants could not be verified."
		result.Evidence = "mysql.user=not_accessible"
		result.HiddenInClientReport = true
		return result
	}
	users := parseUserHosts(output)
	remoteHosts := remoteUserHosts(users)
	result.Evidence = fmt.Sprintf("remote_users=%d; hosts=%s", len(remoteHosts), limitedJoin(remoteHosts, 5))
	if len(remoteHosts) == 0 {
		result.Status = checks.StatusPass
		result.Summary = "No wildcard or public mysql.user hosts were found."
		result.ClientSummary = "Database user host access is restricted."
		return result
	}
	result.Title = "MySQL users allow remote access"
	result.Status = checks.StatusWarn
	result.Summary = "mysql.user contains wildcard or public Host values."
	result.ClientSummary = "Database users may allow remote access."
	return result
}

type checkRootPassword struct{}

func (c checkRootPassword) ID() string { return "mysql.root_password" }
func (c checkRootPassword) Title() string {
	return "MySQL root password is not empty"
}

func (c checkRootPassword) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityCritical, checks.StatusPass)
	result.Summary = "Local MySQL root login without a password did not succeed."
	result.ClientSummary = "Database root account does not appear to allow empty-password login."
	result.AdminDetails = "Attempted a local socket-only mysql -uroot SELECT 1 without supplying a password."
	result.Impact = "An empty database root password can allow immediate full database compromise from local users or exposed sockets."
	result.Recommendation = "Ensure MySQL root and administrative accounts require strong authentication."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Verify the intended authentication plugin and password policy for root accounts.",
		"Set a strong password or socket-auth policy for root using approved database administration procedures.",
		"Confirm applications use dedicated least-privilege accounts, not root.",
	}
	result.Automation = checks.Automation{Shell: `mysql --protocol=socket -uroot -e "SELECT 1"`}

	if !ensureDetected(ctx, &result, "root password check") {
		return result
	}
	_, err := ctx.Runner.Run(ctx.Context, "mysql", "--protocol=socket", "-uroot", "-e", "SELECT 1")
	if err == nil {
		result.Title = "MySQL root accepts empty-password login"
		result.Status = checks.StatusFail
		result.Summary = "Local root login without a password succeeded."
		result.ClientSummary = "Database root account may allow empty-password login."
		result.Evidence = "root_empty_password=true"
		return result
	}
	if mysqlAccessDenied(err) {
		result.Evidence = "root_empty_password=false"
		return result
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Root empty-password test could not access the local MySQL socket."
	result.ClientSummary = "Database root empty-password check could not be verified."
	result.AdminDetails += "\n" + err.Error()
	result.Evidence = "root_empty_password=unknown"
	result.HiddenInClientReport = true
	return result
}

type checkAnonymousUsers struct{}

func (c checkAnonymousUsers) ID() string { return "mysql.anonymous_users" }
func (c checkAnonymousUsers) Title() string {
	return "MySQL anonymous users are absent"
}

func (c checkAnonymousUsers) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "No anonymous MySQL users were found."
	result.ClientSummary = "Database anonymous users were not found."
	result.AdminDetails = "Queried mysql.user for empty User values without collecting password hashes."
	result.Impact = "Anonymous database users can allow unintended access paths and complicate auditing."
	result.Recommendation = "Remove anonymous MySQL users unless a specific, documented use case exists."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review anonymous MySQL users on a maintenance copy or during an approved change window.",
		"Remove anonymous accounts using standard MySQL account management commands.",
		"Retest application access after cleanup.",
	}
	result.Automation = checks.Automation{Shell: `mysql --protocol=socket -NBe "SELECT User, Host FROM mysql.user WHERE User='';"`}

	if !ensureDetected(ctx, &result, "anonymous user check") {
		return result
	}
	output, err := mysqlQuery(ctx, "SELECT User, Host FROM mysql.user WHERE User='';")
	if err != nil {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "mysql.user was not accessible; anonymous users could not be verified."
		result.ClientSummary = "Database anonymous users could not be verified."
		result.Evidence = "anonymous_users=unknown"
		result.HiddenInClientReport = true
		return result
	}
	users := parseUserHosts(output)
	result.Evidence = fmt.Sprintf("anonymous_users=%d", len(users))
	if len(users) > 0 {
		result.Title = "MySQL anonymous users exist"
		result.Status = checks.StatusWarn
		result.Summary = "mysql.user contains anonymous user entries."
		result.ClientSummary = "Database anonymous users should be removed."
	}
	return result
}

type checkInnoDBBufferPool struct {
	cache *discoveryCache
}

func (c checkInnoDBBufferPool) ID() string { return "mysql.innodb_buffer_pool" }
func (c checkInnoDBBufferPool) Title() string {
	return "InnoDB buffer pool is sized"
}

func (c checkInnoDBBufferPool) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "InnoDB buffer pool size is configured within a reasonable range."
	result.ClientSummary = "Database memory sizing is configured."
	result.AdminDetails = "Checked innodb_buffer_pool_size from MySQL configuration and compared it with /proc/meminfo when available."
	result.Impact = "A missing or badly sized buffer pool can reduce performance or consume excessive host memory."
	result.Recommendation = "Set innodb_buffer_pool_size according to workload and available host RAM."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Set innodb_buffer_pool_size to a workload-appropriate value and keep total database memory within host capacity.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^\\s*innodb_buffer_pool_size\" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null; grep MemTotal /proc/meminfo",
		Ansible: ansibleLine("innodb_buffer_pool_size", "1G"),
		Chef:    chefLine("innodb_buffer_pool_size", "1G"),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "InnoDB buffer pool check")
	if !ok {
		return result
	}
	setting := serverSetting(state.config, "innodb_buffer_pool_size")
	ram := readMemTotal(memInfoPath)
	result.Evidence = fmt.Sprintf("innodb_buffer_pool_size=%s; ram_total=%s", valueOrNotSet(setting.Value), formatBytes(ram))
	if setting.Value == "" {
		result.Title = "InnoDB buffer pool size is not configured"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "innodb_buffer_pool_size was not found in MySQL configuration."
		result.ClientSummary = "Database memory limit should be reviewed."
		return result
	}
	size, ok := parseSizeBytes(setting.Value)
	if !ok || ram <= 0 {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "InnoDB buffer pool size is configured; host RAM comparison was not available."
		return result
	}
	if size > ram*80/100 {
		result.Title = "InnoDB buffer pool may be too large"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "innodb_buffer_pool_size is above 80% of host RAM."
		result.ClientSummary = "Database memory setting may be too high."
		return result
	}
	if ram >= 2*1024*1024*1024 && size < ram*5/100 {
		result.Title = "InnoDB buffer pool may be too small"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityLow
		result.Summary = "innodb_buffer_pool_size is below 5% of host RAM."
		result.ClientSummary = "Database memory setting may be too low."
	}
	return result
}

type checkMaxConnections struct {
	cache *discoveryCache
}

func (c checkMaxConnections) ID() string { return "mysql.max_connections" }
func (c checkMaxConnections) Title() string {
	return "MySQL max_connections is reasonable"
}

func (c checkMaxConnections) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "MySQL max_connections is configured within a typical range."
	result.ClientSummary = "Database connection limit was checked."
	result.AdminDetails = "Checked max_connections from configuration, falling back to SHOW VARIABLES when accessible."
	result.Impact = "Very high connection limits can amplify memory pressure and make overload conditions harder to control."
	result.Recommendation = "Set max_connections based on application pool sizes and database memory capacity."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Set max_connections to a value aligned with application pool sizes and available memory.")
	result.Automation = checks.Automation{
		Shell:   `grep -R "^\s*max_connections" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null; mysql --protocol=socket -NBe "SHOW VARIABLES LIKE 'max_connections';"`,
		Ansible: ansibleLine("max_connections", "250"),
		Chef:    chefLine("max_connections", "250"),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "max_connections check")
	if !ok {
		return result
	}
	value := serverSetting(state.config, "max_connections").Value
	source := "config"
	if value == "" {
		if runtime, err := queryVariable(ctx, "max_connections"); err == nil {
			value = runtime
			source = "runtime"
		}
	}
	result.Evidence = fmt.Sprintf("max_connections=%s; source=%s", valueOrNotSet(value), source)
	if value == "" {
		result.Title = "MySQL max_connections could not be verified"
		result.Status = checks.StatusWarn
		result.Summary = "max_connections was not found in configuration and runtime value was not accessible."
		result.ClientSummary = "Database connection limit could not be verified."
		return result
	}
	max, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "max_connections is configured but could not be parsed as an integer."
		return result
	}
	if max > 1000 {
		result.Title = "MySQL max_connections is very high"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "max_connections is above 1000."
		result.ClientSummary = "Database connection limit is high."
	}
	return result
}

type checkTLSEnabled struct {
	cache *discoveryCache
}

func (c checkTLSEnabled) ID() string { return "mysql.tls_enabled" }
func (c checkTLSEnabled) Title() string {
	return "MySQL TLS is enabled where needed"
}

func (c checkTLSEnabled) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "MySQL TLS settings were checked."
	result.ClientSummary = "Database transport encryption was checked."
	result.AdminDetails = "Checked require_secure_transport, ssl_ca, ssl_cert, ssl_key, and runtime TLS variables when accessible."
	result.Impact = "Unencrypted public database traffic can expose credentials and data to network observers."
	result.Recommendation = "Enable require_secure_transport or configure TLS certificates for public or cross-host database access."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Configure require_secure_transport=ON or deploy ssl_ca, ssl_cert, and ssl_key for database listeners used over the network.")
	result.Automation = checks.Automation{
		Shell:   `mysql --protocol=socket -NBe "SHOW VARIABLES LIKE 'have_ssl'; SHOW VARIABLES LIKE 'require_secure_transport';"; grep -R "^\s*ssl_\|^\s*require_secure_transport" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null`,
		Ansible: ansibleLine("require_secure_transport", "ON"),
		Chef:    chefLine("require_secure_transport", "ON"),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "TLS check")
	if !ok {
		return result
	}
	haveSSL := valueOrUnknown(queryVariableOrConfig(ctx, state.config, "have_ssl"))
	requireSecure := valueOrUnknown(queryVariableOrConfig(ctx, state.config, "require_secure_transport"))
	sslCA := serverSetting(state.config, "ssl_ca", "ssl-ca").Value
	sslCert := serverSetting(state.config, "ssl_cert", "ssl-cert").Value
	sslKey := serverSetting(state.config, "ssl_key", "ssl-key").Value
	certsConfigured := sslCA != "" && sslCert != "" && sslKey != ""
	secureTransport := isOn(requireSecure)
	tlsOK := secureTransport || (strings.EqualFold(haveSSL, "YES") && certsConfigured)
	public := networkExposure(state.config, state.listens) == exposurePublic
	result.Evidence = fmt.Sprintf("have_ssl=%s; require_secure_transport=%s; ssl_ca=%s", haveSSL, requireSecure, setEvidence(sslCA != ""))
	if tlsOK {
		result.Status = checks.StatusPass
		result.Severity = checks.SeverityLow
		result.Summary = "MySQL TLS or require_secure_transport is configured."
		result.ClientSummary = "Database transport encryption is configured."
		return result
	}
	if public {
		result.Title = "MySQL TLS is not enforced on a public listener"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "MySQL appears publicly reachable and TLS is not enforced."
		result.ClientSummary = "Database transport encryption should be enabled for public access."
		return result
	}
	result.Summary = "MySQL TLS is not clearly enabled, but the listener does not appear public."
	result.ClientSummary = "Database TLS is not clearly enabled for local-only access."
	return result
}

type checkLogsConfigured struct {
	cache *discoveryCache
}

func (c checkLogsConfigured) ID() string { return "mysql.logs_configured" }
func (c checkLogsConfigured) Title() string {
	return "MySQL logs are configured"
}

func (c checkLogsConfigured) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "MySQL error and slow query logging are configured."
	result.ClientSummary = "Database logging is configured."
	result.AdminDetails = "Checked log_error, slow_query_log, slow_query_log_file, and long_query_time from configuration."
	result.Impact = "Missing database logs reduce visibility during incidents and performance investigations."
	result.Recommendation = "Configure an error log and enable slow query logging where operationally appropriate."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Configure log_error and consider enabling slow_query_log with an appropriate long_query_time.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^\\s*log_error\\|^\\s*slow_query_log\\|^\\s*slow_query_log_file\\|^\\s*long_query_time\" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null",
		Ansible: ansibleLine("slow_query_log", "ON"),
		Chef:    chefLine("slow_query_log", "ON"),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "logging check")
	if !ok {
		return result
	}
	logError := serverSetting(state.config, "log_error", "log-error").Value
	slow := serverSetting(state.config, "slow_query_log", "slow-query-log").Value
	slowFile := serverSetting(state.config, "slow_query_log_file", "slow-query-log-file").Value
	longQuery := serverSetting(state.config, "long_query_time", "long-query-time").Value
	result.Evidence = fmt.Sprintf("log_error=%s; slow_query_log=%s; slow_query_log_file=%s", valueOrNotSet(logError), valueOrNotSet(slow), valueOrNotSet(slowFile))
	if logError == "" {
		result.Title = "MySQL error log is not configured"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "log_error was not found in MySQL configuration."
		result.ClientSummary = "Database error logging should be configured."
		return result
	}
	if !isOn(slow) || slowFile == "" || longQuery == "" {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "MySQL error logging is configured; slow query logging is incomplete or disabled."
		result.ClientSummary = "Database error logging is configured."
	}
	return result
}

type checkBackupsDetected struct{}

func (c checkBackupsDetected) ID() string { return "mysql.backups_detected" }
func (c checkBackupsDetected) Title() string {
	return "MySQL backups are detected"
}

func (c checkBackupsDetected) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "MySQL backup files or backup configuration were detected."
	result.ClientSummary = "Database backup traces were detected."
	result.AdminDetails = "Checked DirectAdmin backup configuration and common backup directories with bounded depth and file count."
	result.Impact = "Missing database backups can turn corruption, accidental deletion, or compromise into permanent data loss."
	result.Recommendation = "Maintain tested MySQL backups with retention, monitoring, and restore drills."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Configure database backups in DirectAdmin or the host backup system.",
		"Store backups with retention and access controls appropriate for database data.",
		"Run restore tests regularly and monitor backup job failures.",
	}
	result.Automation = checks.Automation{Shell: "find /home/admin/admin_backups /home/*/backups /backup /backups /var/backups -maxdepth 3 -type f \\( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.xbstream' \\) 2>/dev/null | head -50"}

	if !ensureDetected(ctx, &result, "backup detection check") {
		return result
	}
	files, configs, permissionErr := backupEvidence()
	result.Evidence = fmt.Sprintf("backup_paths=%s; config_paths=%s", limitedJoin(files, 10), limitedJoin(configs, 10))
	if len(files) > 0 || len(configs) > 0 {
		return result
	}
	if permissionErr {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Backup paths could not be inspected due to permission errors."
		result.ClientSummary = "Database backup traces could not be verified."
		result.Evidence = "backup_paths=permission_denied; config_paths=none"
		result.HiddenInClientReport = true
		return result
	}
	result.Title = "MySQL backups were not detected"
	result.Status = checks.StatusWarn
	result.Summary = "No MySQL backup files or DirectAdmin backup configuration were found in bounded search paths."
	result.ClientSummary = "Database backups were not detected."
	return result
}

type checkConfigPermissions struct {
	cache *discoveryCache
}

func (c checkConfigPermissions) ID() string { return "mysql.error_if_world_writable_config" }
func (c checkConfigPermissions) Title() string {
	return "MySQL config files are not writable by broad principals"
}

func (c checkConfigPermissions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "MySQL configuration file permissions are not group- or world-writable."
	result.ClientSummary = "Database configuration file permissions look restricted."
	result.AdminDetails = "Checked loaded MySQL config files for group-writable and world-writable modes."
	result.Impact = "Writable database configuration files can allow privilege escalation, unsafe listener changes, or credential exposure."
	result.Recommendation = "Keep MySQL config files owned by root or mysql administrators and not writable by group or world."
	result.Remediation = result.Recommendation
	result.RemediationSteps = mysqlConfigSteps("Remove world-writable permissions and review whether group write access is required.")
	result.Automation = checks.Automation{Shell: "find /etc/mysql /etc/my.cnf /etc/my.cnf.d /usr/local/directadmin/conf -maxdepth 3 -type f -name '*.cnf' -o -name 'mysql.conf' 2>/dev/null | xargs -r ls -l"}

	state, ok := loadForResult(ctx, c.cache, &result, "config permission check")
	if !ok {
		return result
	}
	if len(state.config.Files) == 0 {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "MySQL configuration files were not found."
		result.ClientSummary = "Database configuration permissions could not be verified."
		result.Evidence = "config_files=not_found"
		result.HiddenInClientReport = true
		return result
	}
	issues := []string{}
	world := false
	group := false
	for _, path := range state.config.Files {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0002 != 0 {
			world = true
			issues = append(issues, filePermEvidence(path, info))
			continue
		}
		if mode&0020 != 0 {
			group = true
			issues = append(issues, filePermEvidence(path, info))
		}
	}
	result.Evidence = "config_files_checked=" + strconv.Itoa(len(state.config.Files))
	if len(issues) > 0 {
		result.Evidence = limitedJoin(issues, 10)
	}
	if world {
		result.Title = "MySQL config file is world-writable"
		result.Status = checks.StatusFail
		result.Severity = checks.SeverityHigh
		result.Summary = "At least one MySQL configuration file is world-writable."
		result.ClientSummary = "Database configuration permissions are unsafe."
		return result
	}
	if group {
		result.Title = "MySQL config file is group-writable"
		result.Status = checks.StatusWarn
		result.Summary = "At least one MySQL configuration file is group-writable."
		result.ClientSummary = "Database configuration permissions should be reviewed."
	}
	return result
}

type checkSkipNameResolve struct {
	cache *discoveryCache
}

func (c checkSkipNameResolve) ID() string { return "mysql.skip_name_resolve" }
func (c checkSkipNameResolve) Title() string {
	return "MySQL skip-name-resolve setting"
}

func (c checkSkipNameResolve) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "skip-name-resolve is not enabled."
	result.ClientSummary = "Database DNS lookup hardening was checked."
	result.AdminDetails = "Checked skip-name-resolve in MySQL server configuration."
	result.Impact = "Disabling name resolution can reduce connection latency and avoid DNS dependency during authentication checks."
	result.Recommendation = "Consider enabling skip-name-resolve when grants do not depend on hostnames."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^\\s*skip-name-resolve\" /etc/my.cnf /etc/mysql /usr/local/directadmin/conf 2>/dev/null",
		Ansible: ansibleLine("skip-name-resolve", ""),
		Chef:    chefLine("skip-name-resolve", ""),
	}

	state, ok := loadForResult(ctx, c.cache, &result, "skip-name-resolve check")
	if !ok {
		return result
	}
	enabled := serverFlag(state.config, "skip-name-resolve")
	result.Evidence = "skip_name_resolve=" + enabledEvidence(enabled)
	if enabled {
		result.Status = checks.StatusPass
		result.Summary = "skip-name-resolve is enabled."
		result.ClientSummary = "Database DNS lookup hardening is enabled."
	}
	return result
}

func newResult(id, title string, severity checks.Severity, status checks.Status) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, severity, status)
	result.Category = checks.CategoryDatabase
	return result
}

func detect(ctx checks.Context) (bool, string) {
	if !linuxTarget(ctx) {
		return false, "detected=false goos=" + ctx.Host.GOOS
	}
	for _, svc := range ctx.Services {
		unit := strings.ToLower(svc.Unit)
		if unit == "mysqld.service" || unit == "mariadb.service" || unit == "mysql.service" {
			return true, "running_service=" + svc.Unit
		}
	}
	if path, ok := firstExistingPath(mysqlSocketPaths); ok {
		return true, "socket=" + path
	}
	if lookPath != nil {
		for _, binary := range []string{"mysqld", "mariadbd", "mysql", "mariadb"} {
			if path, err := lookPath(binary); err == nil && path != "" {
				return true, "binary=" + path
			}
		}
	}
	if path, ok := firstExistingPath(mysqlBinaryPaths); ok {
		return true, "binary=" + path
	}
	if path, ok := firstExistingPath(mysqlDetectConfigPaths); ok {
		return true, "path_exists=" + path
	}
	return false, "detected=false"
}

func linuxTarget(ctx checks.Context) bool {
	if ctx.Host.GOOS == "" {
		return true
	}
	return ctx.Host.GOOS == "linux" || len(ctx.Host.OSRelease) > 0
}

func ensureDetected(ctx checks.Context, result *checks.Result, checkName string) bool {
	detected, evidence := detect(ctx)
	if detected {
		return true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "MySQL or MariaDB was not detected; " + checkName + " was skipped."
	result.ClientSummary = "MySQL or MariaDB was not detected."
	result.AdminDetails = "This check requires MySQL or MariaDB to be installed or running."
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return false
}

func (c *discoveryCache) load(ctx checks.Context) (discoveryState, bool) {
	if c == nil {
		state := buildDiscovery(ctx)
		return state, state.detected
	}
	if !c.loaded {
		c.state = buildDiscovery(ctx)
		c.loaded = true
	}
	return c.state, c.state.detected
}

func buildDiscovery(ctx checks.Context) discoveryState {
	detected, evidence := detect(ctx)
	state := discoveryState{detected: detected, detectEvidence: evidence}
	if !detected {
		return state
	}
	config, err := loadConfigFromPatterns(mysqlConfigPatterns)
	state.config = config
	state.configErr = err
	state.listens, state.ssErr = collectListens(ctx)
	return state
}

func loadForResult(ctx checks.Context, cache *discoveryCache, result *checks.Result, checkName string) (discoveryState, bool) {
	state, ok := cache.load(ctx)
	if ok {
		if state.configErr == nil && len(state.config.Files) > 0 {
			result.AdminDetails += "\nConfig files: " + limitedJoin(state.config.Files, 5)
		}
		return state, true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "MySQL or MariaDB was not detected; " + checkName + " was skipped."
	result.ClientSummary = "MySQL or MariaDB was not detected."
	result.AdminDetails = "This check requires MySQL or MariaDB to be installed or running."
	result.Evidence = state.detectEvidence
	result.HiddenInClientReport = true
	return discoveryState{}, false
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func mysqlVersion(ctx checks.Context) (string, string, error) {
	type command struct {
		name string
		args []string
	}
	commands := []command{
		{name: "mysqld", args: []string{"--version"}},
		{name: "mariadbd", args: []string{"--version"}},
		{name: "mysql", args: []string{"--version"}},
		{name: "mysqladmin", args: []string{"version"}},
	}
	errs := []string{}
	for _, command := range commands {
		output, err := ctx.Runner.Run(ctx.Context, command.name, command.args...)
		if err != nil {
			errs = append(errs, command.name+": "+err.Error())
			continue
		}
		version := parseVersion(string(output))
		if version == "" {
			errs = append(errs, command.name+": version not found")
			continue
		}
		return version, command.name, nil
	}
	return "", "", errors.New(strings.Join(errs, "; "))
}

var versionRE = regexp.MustCompile(`\b[0-9]+(?:\.[0-9]+){1,3}(?:[-+~][A-Za-z0-9._:-]+)?\b`)

func parseVersion(output string) string {
	match := versionRE.FindString(output)
	return strings.TrimSpace(match)
}

func mysqlQuery(ctx checks.Context, query string) (string, error) {
	output, err := ctx.Runner.Run(ctx.Context, "mysql", "--protocol=socket", "-NBe", query)
	return string(output), err
}

func queryVariable(ctx checks.Context, name string) (string, error) {
	output, err := mysqlQuery(ctx, "SHOW VARIABLES LIKE '"+name+"';")
	if err != nil {
		return "", err
	}
	variables := parseVariableOutput(output)
	if value, ok := variables[name]; ok {
		return value, nil
	}
	return "", fmt.Errorf("variable %s not found", name)
}

func queryVariableOrConfig(ctx checks.Context, config Config, name string) string {
	if value, err := queryVariable(ctx, name); err == nil && value != "" {
		return value
	}
	return serverSetting(config, name).Value
}

func parseVariableOutput(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Fields(line)
		}
		if len(parts) < 2 {
			continue
		}
		values[strings.ToLower(parts[0])] = parts[1]
	}
	return values
}

func serverSetting(config Config, keys ...string) ConfigValue {
	for _, key := range keys {
		if value, ok := config.LastValue(key, serverSections...); ok {
			return value
		}
	}
	return ConfigValue{}
}

func serverFlag(config Config, key string) bool {
	value, ok := config.LastValue(key, serverSections...)
	if !ok {
		return false
	}
	if value.Flag {
		return true
	}
	return isOn(value.Value)
}

type exposure int

const (
	exposureUnknown exposure = iota
	exposureRestricted
	exposurePublic
)

func networkExposure(config Config, listens []listenEndpoint) exposure {
	if serverFlag(config, "skip-networking") {
		return exposureRestricted
	}
	bind := serverSetting(config, "bind-address", "bind_address").Value
	if bind != "" {
		if isPublicAddress(bind) {
			return exposurePublic
		}
		return exposureRestricted
	}
	if len(listens) == 0 {
		return exposureRestricted
	}
	for _, listen := range listens {
		if isPublicAddress(listen.Address) {
			return exposurePublic
		}
	}
	return exposureRestricted
}

type listenEndpoint struct {
	Address string
	Port    string
	Process string
}

func collectListens(ctx checks.Context) ([]listenEndpoint, error) {
	output, err := ctx.Runner.Run(ctx.Context, "ss", "-tulpn")
	if err != nil {
		return nil, err
	}
	return parseSSMySQL(string(output)), nil
}

func parseSSMySQL(output string) []listenEndpoint {
	endpoints := []listenEndpoint{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":330") {
			continue
		}
		lower := strings.ToLower(line)
		if !(strings.Contains(lower, "mysqld") || strings.Contains(lower, "mariadbd") || strings.Contains(lower, "mysql")) {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields {
			address, port, ok := splitEndpoint(field)
			if ok && (port == "3306" || port == "3307") {
				endpoints = append(endpoints, listenEndpoint{Address: address, Port: port, Process: processName(line)})
				break
			}
		}
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Address+endpoints[i].Port < endpoints[j].Address+endpoints[j].Port
	})
	return endpoints
}

func splitEndpoint(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end < 0 {
			return "", "", false
		}
		return strings.Trim(value[1:end], "[]"), value[end+2:], true
	}
	index := strings.LastIndex(value, ":")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return strings.Trim(value[:index], "[]"), value[index+1:], true
}

func processName(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "mariadbd"):
		return "mariadbd"
	case strings.Contains(lower, "mysqld"):
		return "mysqld"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	default:
		return "unknown"
	}
}

func listenEvidence(listens []listenEndpoint) string {
	if len(listens) == 0 {
		return "none"
	}
	parts := []string{}
	for _, listen := range listens {
		parts = append(parts, listen.Address+":"+listen.Port+"/"+listen.Process)
		if len(parts) >= 5 {
			break
		}
	}
	return strings.Join(parts, ",")
}

type userHost struct {
	User string
	Host string
}

func parseUserHosts(output string) []userHost {
	users := []userHost{}
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Fields(line)
		}
		if len(parts) < 2 {
			continue
		}
		users = append(users, userHost{
			User: strings.TrimSpace(parts[0]),
			Host: strings.TrimSpace(parts[1]),
		})
	}
	return users
}

func remoteUserHosts(users []userHost) []string {
	hosts := map[string]bool{}
	for _, user := range users {
		host := strings.TrimSpace(user.Host)
		if host == "" {
			continue
		}
		if dangerousHost(host) {
			hosts[host] = true
		}
	}
	out := []string{}
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func dangerousHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	if lower == "%" || lower == "0.0.0.0" || lower == "::" || strings.ContainsAny(lower, "%_") {
		return true
	}
	if lower == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate())
}

func mysqlAccessDenied(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "access denied") || strings.Contains(lower, "using password: no") || strings.Contains(lower, "authentication")
}

func isPublicAddress(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if lower == "*" || lower == "0.0.0.0" || lower == "::" || lower == "::0" || lower == "::/0" {
		return true
	}
	if lower == "localhost" {
		return false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate())
}

func isOn(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "on" || value == "yes" || value == "true" || value == "enabled"
}

func readMemTotal(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

func parseSizeBytes(value string) (int64, bool) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, false
	}
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(value, "kb"), strings.HasSuffix(value, "k"):
		multiplier = 1024
		value = strings.TrimSuffix(strings.TrimSuffix(value, "kb"), "k")
	case strings.HasSuffix(value, "mb"), strings.HasSuffix(value, "m"):
		multiplier = 1024 * 1024
		value = strings.TrimSuffix(strings.TrimSuffix(value, "mb"), "m")
	case strings.HasSuffix(value, "gb"), strings.HasSuffix(value, "g"):
		multiplier = 1024 * 1024 * 1024
		value = strings.TrimSuffix(strings.TrimSuffix(value, "gb"), "g")
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, false
	}
	return int64(number * float64(multiplier)), true
}

func formatBytes(value int64) string {
	if value <= 0 {
		return "unknown"
	}
	const gb = 1024 * 1024 * 1024
	const mb = 1024 * 1024
	if value >= gb {
		return fmt.Sprintf("%.1fGB", float64(value)/gb)
	}
	return fmt.Sprintf("%.0fMB", float64(value)/mb)
}

func backupEvidence() ([]string, []string, bool) {
	configs := globExisting(mysqlBackupConfigPatterns, 10)
	files := []string{}
	permissionErr := false
	for _, rootPattern := range mysqlBackupRoots {
		roots, err := filepath.Glob(rootPattern)
		if err != nil || len(roots) == 0 {
			if _, statErr := os.Stat(rootPattern); statErr == nil {
				roots = []string{rootPattern}
			}
		}
		sort.Strings(roots)
		for _, root := range roots {
			found, denied := findBackupFiles(root, 3, 50-len(files))
			if denied {
				permissionErr = true
			}
			files = append(files, found...)
			if len(files) >= 50 {
				return files, configs, permissionErr
			}
		}
	}
	return files, configs, permissionErr
}

func globExisting(patterns []string, limit int) []string {
	out := []string{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			if _, statErr := os.Stat(pattern); statErr == nil {
				matches = []string{pattern}
			}
		}
		sort.Strings(matches)
		for _, match := range matches {
			if _, err := os.Stat(match); err == nil {
				out = append(out, match)
				if limit > 0 && len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
}

func findBackupFiles(root string, maxDepth, limit int) ([]string, bool) {
	if limit <= 0 {
		return nil, false
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, os.IsPermission(err)
	}
	files := []string{}
	denied := false
	root = filepath.Clean(root)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				denied = true
			}
			return nil
		}
		if len(files) >= limit {
			return filepath.SkipAll
		}
		depth := pathDepth(root, path)
		if d.IsDir() && depth > maxDepth {
			return filepath.SkipDir
		}
		if d.IsDir() || depth > maxDepth {
			return nil
		}
		if backupFileName(d.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil && os.IsPermission(err) {
		denied = true
	}
	return files, denied
}

func pathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}

func backupFileName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".sql") || strings.HasSuffix(lower, ".sql.gz") || strings.HasSuffix(lower, ".dump") || strings.HasSuffix(lower, ".xbstream")
}

func filePermEvidence(path string, info fs.FileInfo) string {
	owner, group := ownerGroup(info)
	return fmt.Sprintf("path=%s mode=%04o owner=%s group=%s", path, info.Mode().Perm(), owner, group)
}

func ownerGroup(info fs.FileInfo) (string, string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown", "unknown"
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	ownerName := uid
	groupName := gid
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		ownerName = u.Username + "(" + uid + ")"
	}
	if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
		groupName = g.Name + "(" + gid + ")"
	}
	return ownerName, groupName
}

func valueOrNotSet(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "not_set"
	}
	return value
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func setEvidence(ok bool) string {
	if ok {
		return "set"
	}
	return "not_set"
}

func enabledEvidence(ok bool) string {
	if ok {
		return "enabled"
	}
	return "disabled"
}

func limitedJoin(values []string, limit int) string {
	if len(values) == 0 {
		return "none"
	}
	if limit <= 0 || limit > len(values) {
		limit = len(values)
	}
	return strings.Join(values[:limit], ",")
}

func mysqlConfigSteps(action string) []string {
	return []string{
		"Review the active MySQL or MariaDB configuration files.",
		action,
		"Validate the change and apply it during an approved database maintenance window.",
	}
}

func ansibleLine(key, value string) string {
	line := key
	if value != "" {
		line += " = " + value
	}
	return "- name: Configure MySQL " + key + "\n  ansible.builtin.lineinfile:\n    path: /etc/mysql/my.cnf\n    regexp: '^\\\\s*" + regexp.QuoteMeta(key) + "\\\\b'\n    line: '" + line + "'\n  notify: restart mysql"
}

func chefLine(key, value string) string {
	line := key
	if value != "" {
		line += " = " + value
	}
	return "ruby_block 'configure mysql " + key + "' do\n  block { Chef::Util::FileEdit.new('/etc/mysql/my.cnf').search_file_replace_line(/^\\s*" + regexp.QuoteMeta(key) + "\\b/, '" + line + "').write_file }\nend"
}
