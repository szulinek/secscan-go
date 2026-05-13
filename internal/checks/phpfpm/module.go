package phpfpm

import (
	"fmt"
	"os"
	pathmatch "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "php_fpm"
	service  = "php-fpm"

	sourceDirectAdmin = "directadmin"
	sourceSystem      = "system"
)

var (
	directAdminPHPBinaryGlobs = []string{"/usr/local/php*/bin/php"}
	directAdminFPMBinaryGlobs = []string{"/usr/local/php*/sbin/php-fpm"}
	directAdminINIGlobs       = []string{"/usr/local/php*/lib/php.ini"}
	directAdminPoolGlobs      = []string{"/usr/local/php*/etc/php-fpm.conf", "/usr/local/php*/etc/php-fpm.d/*.conf", "/usr/local/directadmin/data/users/*/php/*"}

	systemPHPBinaryGlobs = []string{"/usr/bin/php", "/usr/bin/php[0-9]*", "/usr/local/bin/php", "/usr/local/bin/php[0-9]*"}
	systemFPMBinaryGlobs = []string{"/usr/sbin/php-fpm", "/usr/sbin/php-fpm[0-9]*", "/usr/local/sbin/php-fpm", "/usr/local/sbin/php-fpm[0-9]*"}
	systemFPMINIGlobs    = []string{"/etc/php/*/fpm/php.ini"}
	systemCLIINIGlobs    = []string{"/etc/php/*/cli/php.ini"}
	systemPoolGlobs      = []string{"/etc/php/*/fpm/pool.d/*.conf"}

	memInfoPath = "/proc/meminfo"
)

type Module struct{}

type discoveryCache struct {
	loaded bool
	state  discoveryState
}

type discoveryState struct {
	Versions []PHPVersion
	INI      []INIFile
	Pools    []PoolConfig
	Errors   []string
}

type PHPVersion struct {
	Version    string
	SAPI       string
	Source     string
	SourcePath string
}

type INIFile struct {
	Version string
	SAPI    string
	Source  string
	Path    string
	Config  INIConfig
}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "PHP-FPM"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &discoveryCache{}
	return []checks.Check{
		checkAvailableVersions{cache: cache},
		checkPMMaxChildren{cache: cache},
		checkDisabledFunctions{cache: cache},
		checkOpenBasedir{cache: cache},
		checkLogsConfigured{cache: cache},
		checkSessionCookieSecurity{cache: cache},
		checkExposePHP{cache: cache},
		checkDisplayErrors{cache: cache},
		checkPoolUser{cache: cache},
		checkPoolSocketSecurity{cache: cache},
	}
}

type checkAvailableVersions struct {
	cache *discoveryCache
}

func (c checkAvailableVersions) ID() string {
	return "php.available_versions"
}

func (c checkAvailableVersions) Title() string {
	return "PHP versions detected"
}

func (c checkAvailableVersions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "PHP versions were inventoried."
	result.ClientSummary = "PHP versions were recorded for the audit."
	result.AdminDetails = "Discovered PHP versions from DirectAdmin paths, system PHP paths, php.ini files, pool configs, and version commands."
	result.Impact = "PHP version inventory helps plan security updates, application compatibility work, and end-of-life migrations."
	result.Recommendation = "Keep every PHP version supported and patched, and remove unused runtimes."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "php -v; php-fpm -v; find /usr/local/php* /etc/php -maxdepth 4 -type f 2>/dev/null"}
	result.HiddenInClientReport = true

	state := c.cache.load(ctx)
	if len(state.Versions) == 0 {
		result.Evidence = "php_versions=not_found"
		result.Summary = "No PHP versions were discovered."
		return result
	}

	result.Evidence = versionsEvidence(state.Versions, 15)
	return result
}

type checkPMMaxChildren struct {
	cache *discoveryCache
}

func (c checkPMMaxChildren) ID() string {
	return "php.pm_max_children"
}

func (c checkPMMaxChildren) Title() string {
	return "PHP-FPM pm.max_children is configured"
}

func (c checkPMMaxChildren) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP-FPM pools define pm.max_children."
	result.ClientSummary = "PHP-FPM worker limits are configured."
	result.AdminDetails = "Parsed PHP-FPM pool configs, including DirectAdmin user pools, and checked pm.max_children."
	result.Impact = "Missing or excessive PHP-FPM worker limits can exhaust memory under load."
	result.Recommendation = "Set pm.max_children per pool based on available memory and workload."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set pm.max_children to a workload-appropriate value in each active pool.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^pm.max_children\" /usr/local/php*/etc /usr/local/directadmin/data/users/*/php /etc/php/*/fpm/pool.d 2>/dev/null",
		Ansible: ansibleLine("pm.max_children", "40", "/etc/php/{{ php_version }}/fpm/pool.d/www.conf"),
		Chef:    chefLine("pm.max_children", "40", "/etc/php/8.2/fpm/pool.d/www.conf"),
	}

	pools, ok := poolsForResult(ctx, c.cache, &result, "pm.max_children check")
	if !ok {
		return result
	}
	pools = workerPools(pools)
	if len(pools) == 0 {
		return notApplicable(result, "pools=not_found", "No PHP-FPM worker pools were found.")
	}

	totalMem, _ := memTotalBytes(memInfoPath)
	issues := []PoolConfig{}
	for _, pool := range pools {
		value := poolValue(pool, "pm.max_children")
		if strings.TrimSpace(value) == "" {
			issues = append(issues, pool)
			continue
		}
		intValue, err := strconv.Atoi(value)
		if err != nil || intValue <= 0 || pmMaxChildrenTooHigh(intValue, totalMem) {
			issues = append(issues, pool)
		}
	}

	result.Evidence = pmEvidence(pools, 10)
	if len(issues) > 0 {
		result.Title = "PHP-FPM pm.max_children needs review"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP-FPM pools are missing pm.max_children or use a very high value."
		result.ClientSummary = "Some PHP-FPM worker limits need administrator review."
		result.Evidence = pmEvidence(issues, 10)
	}
	return result
}

type checkDisabledFunctions struct {
	cache *discoveryCache
}

func (c checkDisabledFunctions) ID() string {
	return "php.disabled_functions"
}

func (c checkDisabledFunctions) Title() string {
	return "PHP disabled_functions is configured"
}

func (c checkDisabledFunctions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP disabled_functions is configured."
	result.ClientSummary = "PHP dangerous-function restrictions are configured."
	result.AdminDetails = "Parsed disable_functions from discovered php.ini files."
	result.Impact = "An unrestricted PHP function surface can increase post-exploitation options for vulnerable applications."
	result.Recommendation = "Configure disable_functions according to application compatibility and hosting policy."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set disable_functions to a policy-approved list for each active PHP runtime.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^disable_functions\" /usr/local/php*/lib/php.ini /etc/php/*/*/php.ini 2>/dev/null",
		Ansible: ansibleLine("disable_functions", "exec,passthru,shell_exec,system,proc_open,popen", "{{ php_ini_path }}"),
		Chef:    chefLine("disable_functions", "exec,passthru,shell_exec,system,proc_open,popen", "/etc/php/8.2/fpm/php.ini"),
	}

	values, ok := iniValuesForResult(ctx, c.cache, &result, "disable_functions", "disabled_functions check")
	if !ok {
		return result
	}

	issues := []INIValue{}
	for _, value := range values {
		if strings.TrimSpace(value.Value) == "" || value.Missing {
			issues = append(issues, value)
		}
	}
	result.Evidence = disabledFunctionsEvidence(values, 10)
	if len(issues) > 0 {
		result.Title = "PHP disabled_functions is empty or missing"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP runtimes have empty or missing disabled_functions."
		result.ClientSummary = "PHP dangerous-function restrictions are not configured everywhere."
		result.Evidence = disabledFunctionsEvidence(issues, 10)
	}
	return result
}

type checkOpenBasedir struct {
	cache *discoveryCache
}

func (c checkOpenBasedir) ID() string {
	return "php.open_basedir"
}

func (c checkOpenBasedir) Title() string {
	return "PHP open_basedir is configured"
}

func (c checkOpenBasedir) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP open_basedir is configured."
	result.ClientSummary = "PHP filesystem path restrictions are configured."
	result.AdminDetails = "Parsed open_basedir from php.ini and PHP-FPM pool php_admin_value/php_value overrides."
	result.Impact = "Missing open_basedir can allow compromised PHP code to read broader filesystem paths than intended."
	result.Recommendation = "Configure open_basedir per application pool where compatibility allows."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set open_basedir in php.ini or per-pool php_admin_value for each hosted application.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"open_basedir\" /usr/local/php*/lib/php.ini /usr/local/php*/etc /usr/local/directadmin/data/users/*/php /etc/php 2>/dev/null",
		Ansible: ansibleLine("php_admin_value[open_basedir]", "/home/{{ app_user }}:/tmp", "{{ php_pool_path }}"),
		Chef:    chefLine("php_admin_value[open_basedir]", "/home/app:/tmp", "/etc/php/8.2/fpm/pool.d/www.conf"),
	}

	state, ok := stateForResult(ctx, c.cache, &result, "open_basedir check")
	if !ok {
		return result
	}

	values := openBasedirValues(state)
	result.Evidence = configValueEvidence(values, "open_basedir", 10)
	if len(values) == 0 || allMissing(values) {
		result.Title = "PHP open_basedir is not configured"
		result.Status = checks.StatusWarn
		result.Summary = "No open_basedir setting was found in discovered PHP configs."
		result.ClientSummary = "PHP filesystem path restrictions are not configured."
		result.Evidence = "open_basedir=not_set"
	}
	return result
}

type checkLogsConfigured struct {
	cache *discoveryCache
}

func (c checkLogsConfigured) ID() string {
	return "php.logs_configured"
}

func (c checkLogsConfigured) Title() string {
	return "PHP error logging is configured"
}

func (c checkLogsConfigured) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP error logging is configured."
	result.ClientSummary = "PHP error logging is configured."
	result.AdminDetails = "Parsed PHP error_log and PHP-FPM pool access.log, php_admin_value[error_log], and php_admin_value[mail.log]."
	result.Impact = "Missing or disabled PHP error logs make incident response and application troubleshooting harder."
	result.Recommendation = "Configure PHP error logs to a persistent path and avoid /dev/null for application error logs."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set error_log to a persistent file path for active runtimes or pools.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"\\(error_log\\|access.log\\|mail.log\\)\" /usr/local/php*/lib/php.ini /usr/local/php*/etc /usr/local/directadmin/data/users/*/php /etc/php 2>/dev/null",
		Ansible: ansibleLine("php_admin_value[error_log]", "/var/log/php-fpm/$pool-error.log", "{{ php_pool_path }}"),
		Chef:    chefLine("php_admin_value[error_log]", "/var/log/php-fpm/www-error.log", "/etc/php/8.2/fpm/pool.d/www.conf"),
	}

	state, ok := stateForResult(ctx, c.cache, &result, "logs check")
	if !ok {
		return result
	}

	logs := logSettings(state)
	result.Evidence = logsEvidence(logs, 10)
	if logs.ErrorLog == "" || strings.EqualFold(logs.ErrorLog, "/dev/null") {
		result.Title = "PHP error logging needs review"
		result.Status = checks.StatusWarn
		result.Summary = "PHP error_log is missing or points to /dev/null."
		result.ClientSummary = "PHP error logging is missing or disabled."
	}
	return result
}

type checkSessionCookieSecurity struct {
	cache *discoveryCache
}

func (c checkSessionCookieSecurity) ID() string {
	return "php.session_cookie_security"
}

func (c checkSessionCookieSecurity) Title() string {
	return "PHP session cookies are hardened"
}

func (c checkSessionCookieSecurity) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP session cookie security settings are configured."
	result.ClientSummary = "PHP session cookies are hardened."
	result.AdminDetails = "Parsed session.cookie_secure, session.cookie_httponly, and session.cookie_samesite from php.ini files."
	result.Impact = "Weak session cookie settings increase exposure to session theft over plaintext links or client-side script access."
	result.Recommendation = "Enable secure and httponly session cookies and set an appropriate SameSite policy."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set session.cookie_secure=1, session.cookie_httponly=1, and session.cookie_samesite to Lax or Strict.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^session.cookie_\" /usr/local/php*/lib/php.ini /etc/php/*/*/php.ini 2>/dev/null",
		Ansible: ansibleLine("session.cookie_secure", "1", "{{ php_ini_path }}"),
		Chef:    chefLine("session.cookie_secure", "1", "/etc/php/8.2/fpm/php.ini"),
	}

	state, ok := stateForResult(ctx, c.cache, &result, "session cookie check")
	if !ok {
		return result
	}

	security := sessionCookieSecurity(state.INI)
	result.Evidence = fmt.Sprintf("secure=%s; httponly=%s; samesite=%s", security.Secure, security.HTTPOnly, security.SameSite)
	if !truthy(security.Secure) || !truthy(security.HTTPOnly) || strings.TrimSpace(security.SameSite) == "" || security.SameSite == "not_set" {
		result.Title = "PHP session cookie settings need hardening"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP session cookie security settings are missing or disabled."
		result.ClientSummary = "PHP session cookie settings should be hardened."
	}
	return result
}

type checkExposePHP struct {
	cache *discoveryCache
}

func (c checkExposePHP) ID() string {
	return "php.expose_php"
}

func (c checkExposePHP) Title() string {
	return "PHP expose_php is disabled"
}

func (c checkExposePHP) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "PHP expose_php is disabled."
	result.ClientSummary = "PHP version disclosure is disabled."
	result.AdminDetails = "Parsed expose_php from discovered php.ini files."
	result.Impact = "PHP version disclosure makes fingerprinting easier for automated scanners."
	result.Recommendation = "Set expose_php=Off in every active PHP php.ini."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set expose_php=Off in each active php.ini.")
	result.References = []string{"https://www.php.net/manual/en/ini.core.php#ini.expose-php"}
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^expose_php\" /usr/local/php*/lib/php.ini /etc/php/*/*/php.ini 2>/dev/null",
		Ansible: ansibleLine("expose_php", "Off", "{{ php_ini_path }}"),
		Chef:    chefLine("expose_php", "Off", "/etc/php/8.2/fpm/php.ini"),
	}

	values, ok := iniValuesForResult(ctx, c.cache, &result, "expose_php", "expose_php check")
	if !ok {
		return result
	}

	issues := []INIValue{}
	for _, value := range values {
		if value.Missing || !isOff(value.Value) {
			issues = append(issues, value)
		}
	}
	result.Evidence = iniValueEvidence(values, 10)
	if len(issues) > 0 {
		result.Title = "PHP expose_php is enabled or missing"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP runtimes do not explicitly disable expose_php."
		result.ClientSummary = "PHP version disclosure may be enabled."
		result.Evidence = iniValueEvidence(issues, 10)
	}
	return result
}

type checkDisplayErrors struct {
	cache *discoveryCache
}

func (c checkDisplayErrors) ID() string {
	return "php.display_errors"
}

func (c checkDisplayErrors) Title() string {
	return "PHP display_errors is disabled"
}

func (c checkDisplayErrors) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "PHP display_errors is disabled."
	result.ClientSummary = "PHP runtime errors are not displayed to visitors."
	result.AdminDetails = "Parsed display_errors from discovered php.ini files."
	result.Impact = "Displayed PHP errors can leak filesystem paths, SQL details, and application internals."
	result.Recommendation = "Set display_errors=Off in production PHP php.ini files."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set display_errors=Off in each production php.ini.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^display_errors\" /usr/local/php*/lib/php.ini /etc/php/*/*/php.ini 2>/dev/null",
		Ansible: ansibleLine("display_errors", "Off", "{{ php_ini_path }}"),
		Chef:    chefLine("display_errors", "Off", "/etc/php/8.2/fpm/php.ini"),
	}

	values, ok := iniValuesForResult(ctx, c.cache, &result, "display_errors", "display_errors check")
	if !ok {
		return result
	}

	issues := []INIValue{}
	for _, value := range values {
		if !value.Missing && !isOff(value.Value) {
			issues = append(issues, value)
		}
	}
	result.Evidence = iniValueEvidence(values, 10)
	if len(issues) > 0 {
		result.Title = "PHP display_errors is enabled"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP runtimes have display_errors enabled."
		result.ClientSummary = "PHP errors may be shown to visitors."
		result.Evidence = iniValueEvidence(issues, 10)
	}
	return result
}

type checkPoolUser struct {
	cache *discoveryCache
}

func (c checkPoolUser) ID() string {
	return "php.pool_user"
}

func (c checkPoolUser) Title() string {
	return "PHP-FPM pools do not run as root"
}

func (c checkPoolUser) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "PHP-FPM pools do not run as root."
	result.ClientSummary = "PHP-FPM pools do not run as root."
	result.AdminDetails = "Parsed user and group directives from PHP-FPM pool configs, including DirectAdmin user pools."
	result.Impact = "A PHP-FPM pool running as root can turn an application compromise into full host compromise."
	result.Recommendation = "Run PHP-FPM pools as dedicated unprivileged users, never root."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Set user and group to an unprivileged account for each active pool.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^\\(user\\|group\\)\" /usr/local/php*/etc /usr/local/directadmin/data/users/*/php /etc/php/*/fpm/pool.d 2>/dev/null",
		Ansible: ansibleLine("user", "www-data", "/etc/php/{{ php_version }}/fpm/pool.d/www.conf"),
		Chef:    chefLine("user", "www-data", "/etc/php/8.2/fpm/pool.d/www.conf"),
	}

	pools, ok := poolsForResult(ctx, c.cache, &result, "pool user check")
	if !ok {
		return result
	}
	pools = workerPools(pools)
	if len(pools) == 0 {
		return notApplicable(result, "pools=not_found", "No PHP-FPM worker pools were found.")
	}

	rootPools := []PoolConfig{}
	for _, pool := range pools {
		if strings.EqualFold(poolValue(pool, "user"), "root") {
			rootPools = append(rootPools, pool)
		}
	}
	result.Evidence = poolUserEvidence(pools, 10)
	if len(rootPools) > 0 {
		result.Title = "PHP-FPM pool runs as root"
		result.Status = checks.StatusFail
		result.Summary = "One or more PHP-FPM pools are configured to run as root."
		result.ClientSummary = "A PHP-FPM pool is running with root privileges."
		result.Evidence = poolUserEvidence(rootPools, 10)
	}
	return result
}

type checkPoolSocketSecurity struct {
	cache *discoveryCache
}

func (c checkPoolSocketSecurity) ID() string {
	return "php.pool_socket_security"
}

func (c checkPoolSocketSecurity) Title() string {
	return "PHP-FPM pool sockets are restricted"
}

func (c checkPoolSocketSecurity) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "PHP-FPM pool socket paths and modes look restricted."
	result.ClientSummary = "PHP-FPM socket permissions look restricted."
	result.AdminDetails = "Parsed listen and listen.mode from PHP-FPM pool configs."
	result.Impact = "Broad PHP-FPM socket access can allow unintended local users or services to send requests to PHP workers."
	result.Recommendation = "Keep PHP-FPM sockets outside /tmp and use restrictive listen.mode values such as 0660 or 0600."
	result.Remediation = result.Recommendation
	result.RemediationSteps = phpConfigSteps("Move sockets out of /tmp and set listen.mode to 0660 or stricter where Unix sockets are used.")
	result.Automation = checks.Automation{
		Shell:   "grep -R \"^listen\\|^listen.mode\" /usr/local/php*/etc /usr/local/directadmin/data/users/*/php /etc/php/*/fpm/pool.d 2>/dev/null",
		Ansible: ansibleLine("listen.mode", "0660", "/etc/php/{{ php_version }}/fpm/pool.d/www.conf"),
		Chef:    chefLine("listen.mode", "0660", "/etc/php/8.2/fpm/pool.d/www.conf"),
	}

	pools, ok := poolsForResult(ctx, c.cache, &result, "pool socket check")
	if !ok {
		return result
	}

	issues := []PoolConfig{}
	for _, pool := range pools {
		listen := poolValue(pool, "listen")
		mode := poolValue(pool, "listen.mode")
		if socketInTmp(listen) || listenModeTooWide(mode) {
			issues = append(issues, pool)
		}
	}
	result.Evidence = poolSocketEvidence(pools, 10)
	if len(issues) > 0 {
		result.Title = "PHP-FPM pool socket settings need review"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "One or more PHP-FPM pools use /tmp sockets or broad listen.mode values."
		result.ClientSummary = "Some PHP-FPM socket settings should be tightened."
		result.Evidence = poolSocketEvidence(issues, 10)
	}
	return result
}

func newResult(id, title string, severity checks.Severity, status checks.Status) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, severity, status)
	result.Category = checks.CategoryWeb
	return result
}

func detect(ctx checks.Context) (bool, string) {
	for _, svc := range ctx.Services {
		unit := strings.ToLower(svc.Unit)
		if unit == "php-fpm.service" {
			return true, "running_service=" + svc.Unit
		}
		if matched, err := pathmatch.Match("php*-fpm.service", unit); err == nil && matched {
			return true, "running_service=" + svc.Unit
		}
	}

	if path, ok := firstExistingPath(expandGlobs(directAdminFPMBinaryGlobs, systemFPMBinaryGlobs, directAdminPHPBinaryGlobs, systemPHPBinaryGlobs)); ok {
		return true, "path_exists=" + path
	}
	if path, ok := firstExistingPath(expandGlobs(directAdminINIGlobs, systemFPMINIGlobs, systemCLIINIGlobs, directAdminPoolGlobs, systemPoolGlobs)); ok {
		return true, "path_exists=" + path
	}
	return false, "detected=false"
}

func (c *discoveryCache) load(ctx checks.Context) discoveryState {
	if c == nil {
		return discover(ctx)
	}
	if !c.loaded {
		c.state = discover(ctx)
		c.loaded = true
	}
	return c.state
}

func discover(ctx checks.Context) discoveryState {
	state := discoveryState{}
	state.Versions = append(state.Versions, commandVersions(ctx)...)
	state.Versions = append(state.Versions, discoverDirectAdminVersions()...)
	state.Versions = append(state.Versions, discoverSystemVersions()...)
	state.INI = append(state.INI, discoverINI(directAdminINIGlobs, sourceDirectAdmin, "fpm")...)
	state.INI = append(state.INI, discoverINI(systemFPMINIGlobs, sourceSystem, "fpm")...)
	state.INI = append(state.INI, discoverINI(systemCLIINIGlobs, sourceSystem, "cli")...)

	pools, errors := discoverPools()
	state.Pools = pools
	state.Errors = errors

	for _, ini := range state.INI {
		state.Versions = append(state.Versions, PHPVersion{Version: ini.Version, SAPI: ini.SAPI, Source: ini.Source, SourcePath: ini.Path})
	}
	for _, pool := range state.Pools {
		state.Versions = append(state.Versions, PHPVersion{Version: pool.Version, SAPI: "fpm", Source: pool.Source, SourcePath: pool.Path})
	}
	state.Versions = uniqueVersions(state.Versions)
	sortVersions(state.Versions)
	sortINI(state.INI)
	sortPools(state.Pools)
	return state
}

func commandVersions(ctx checks.Context) []PHPVersion {
	if ctx.Runner == nil {
		return nil
	}

	out := []PHPVersion{}
	if output, err := ctx.Runner.Run(ctx.Context, "php", "-v"); err == nil {
		if version := parsePHPVersion(string(output)); version != "" {
			out = append(out, PHPVersion{Version: version, SAPI: "cli", Source: sourceSystem, SourcePath: "php -v"})
		}
	}
	if output, err := ctx.Runner.Run(ctx.Context, "php-fpm", "-v"); err == nil {
		if version := parsePHPVersion(string(output)); version != "" {
			out = append(out, PHPVersion{Version: version, SAPI: "fpm", Source: sourceSystem, SourcePath: "php-fpm -v"})
		}
	}
	return out
}

func discoverDirectAdminVersions() []PHPVersion {
	versions := []PHPVersion{}
	for _, path := range globAll(directAdminPHPBinaryGlobs) {
		versions = append(versions, PHPVersion{Version: versionFromDirectAdminPath(path), SAPI: "cli", Source: sourceDirectAdmin, SourcePath: path})
	}
	for _, path := range globAll(directAdminFPMBinaryGlobs) {
		versions = append(versions, PHPVersion{Version: versionFromDirectAdminPath(path), SAPI: "fpm", Source: sourceDirectAdmin, SourcePath: path})
	}
	return versions
}

func discoverSystemVersions() []PHPVersion {
	versions := []PHPVersion{}
	for _, path := range globAll(systemPHPBinaryGlobs) {
		versions = append(versions, PHPVersion{Version: versionFromSystemPath(path), SAPI: "cli", Source: sourceSystem, SourcePath: path})
	}
	for _, path := range globAll(systemFPMBinaryGlobs) {
		versions = append(versions, PHPVersion{Version: versionFromSystemPath(path), SAPI: "fpm", Source: sourceSystem, SourcePath: path})
	}
	return versions
}

func discoverINI(patterns []string, source, sapi string) []INIFile {
	files := []INIFile{}
	for _, path := range globAll(patterns) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		files = append(files, INIFile{
			Version: versionFromPath(path, source),
			SAPI:    sapi,
			Source:  source,
			Path:    path,
			Config:  ParseINI(string(data)),
		})
	}
	return files
}

func discoverPools() ([]PoolConfig, []string) {
	pools := []PoolConfig{}
	errors := []string{}
	for _, sourcePatterns := range []struct {
		source   string
		patterns []string
	}{
		{source: sourceDirectAdmin, patterns: directAdminPoolGlobs},
		{source: sourceSystem, patterns: systemPoolGlobs},
	} {
		for _, path := range globAll(sourcePatterns.patterns) {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				errors = append(errors, filepath.Base(path)+"=read_error")
				continue
			}
			version := versionFromPath(path, sourcePatterns.source)
			pools = append(pools, ParsePoolConfig(version, sourcePatterns.source, path, string(data))...)
		}
	}
	return pools, errors
}

func stateForResult(ctx checks.Context, cache *discoveryCache, result *checks.Result, checkName string) (discoveryState, bool) {
	if !ensurePHPDetected(ctx, result, checkName) {
		return discoveryState{}, false
	}
	state := cache.load(ctx)
	if len(state.Errors) > 0 {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "PHP configuration could not be read completely."
		result.ClientSummary = "PHP configuration could not be verified."
		result.AdminDetails = "Read errors while discovering PHP configuration."
		result.Evidence = joinEvidence(state.Errors, 5)
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return discoveryState{}, false
	}
	return state, true
}

func poolsForResult(ctx checks.Context, cache *discoveryCache, result *checks.Result, checkName string) ([]PoolConfig, bool) {
	state, ok := stateForResult(ctx, cache, result, checkName)
	if !ok {
		return nil, false
	}
	if len(state.Pools) == 0 {
		*result = notApplicable(*result, "pools=not_found", "No PHP-FPM pool configuration files were found.")
		return nil, false
	}
	return state.Pools, true
}

type INIValue struct {
	Version string
	SAPI    string
	Source  string
	Path    string
	Key     string
	Value   string
	Missing bool
}

func iniValuesForResult(ctx checks.Context, cache *discoveryCache, result *checks.Result, key, checkName string) ([]INIValue, bool) {
	state, ok := stateForResult(ctx, cache, result, checkName)
	if !ok {
		return nil, false
	}
	if len(state.INI) == 0 {
		*result = notApplicable(*result, "php_ini=not_found", "No PHP ini files were found.")
		return nil, false
	}
	return iniValues(state.INI, key), true
}

func iniValues(files []INIFile, key string) []INIValue {
	values := []INIValue{}
	key = strings.ToLower(key)
	for _, file := range files {
		value, ok := file.Config.Values[key]
		values = append(values, INIValue{
			Version: file.Version,
			SAPI:    file.SAPI,
			Source:  file.Source,
			Path:    file.Path,
			Key:     key,
			Value:   value,
			Missing: !ok,
		})
	}
	return values
}

func ensurePHPDetected(ctx checks.Context, result *checks.Result, checkName string) bool {
	detected, evidence := detect(ctx)
	if detected {
		return true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "PHP-FPM was not detected; " + checkName + " was skipped."
	result.ClientSummary = "PHP-FPM was not detected."
	result.AdminDetails = "This check requires PHP-FPM or PHP configuration to be present."
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return false
}

func notApplicable(result checks.Result, evidence, summary string) checks.Result {
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = summary
	result.ClientSummary = summary
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return result
}

func versionsEvidence(versions []PHPVersion, limit int) string {
	parts := []string{}
	for _, version := range versions {
		parts = append(parts, fmt.Sprintf("version=%s sapi=%s source_type=%s source_path=%s", evidenceValue(version.Version), version.SAPI, version.Source, version.SourcePath))
	}
	return joinEvidence(parts, limit)
}

func pmEvidence(pools []PoolConfig, limit int) string {
	parts := []string{}
	for _, pool := range pools {
		parts = append(parts, fmt.Sprintf("pool=%s/%s pm.max_children=%s source=%s", pool.Version, pool.Pool, evidenceValue(poolValue(pool, "pm.max_children")), pool.Source))
	}
	return joinEvidence(parts, limit)
}

func disabledFunctionsEvidence(values []INIValue, limit int) string {
	parts := []string{}
	for _, value := range values {
		functions := splitCSV(value.Value)
		if value.Missing || len(functions) == 0 {
			parts = append(parts, fmt.Sprintf("source=%s/%s disable_functions=count=0", value.Source, value.Version))
			continue
		}
		parts = append(parts, fmt.Sprintf("source=%s/%s disable_functions=count=%d funcs=%s", value.Source, value.Version, len(functions), strings.Join(limitStrings(functions, 10), ",")))
	}
	return joinEvidence(parts, limit)
}

type ConfigValue struct {
	Source string
	Path   string
	Value  string
	Set    bool
}

func openBasedirValues(state discoveryState) []ConfigValue {
	values := []ConfigValue{}
	for _, file := range state.INI {
		value, ok := file.Config.Values["open_basedir"]
		if ok && strings.TrimSpace(value) != "" {
			values = append(values, ConfigValue{Source: file.Source + "/" + file.Version, Path: file.Path, Value: value, Set: true})
		}
	}
	for _, pool := range state.Pools {
		for _, valuesMap := range []map[string]string{pool.PHPAdminValues, pool.PHPValues} {
			if value, ok := valuesMap["open_basedir"]; ok && strings.TrimSpace(value) != "" {
				values = append(values, ConfigValue{Source: pool.Source + "/" + pool.Pool, Path: pool.Path, Value: value, Set: true})
			}
		}
	}
	return values
}

func configValueEvidence(values []ConfigValue, key string, limit int) string {
	if len(values) == 0 {
		return key + "=not_set"
	}
	parts := []string{}
	for _, value := range values {
		state := "not_set"
		if value.Set {
			state = "set"
		}
		parts = append(parts, fmt.Sprintf("source=%s %s=%s value=%s", value.Source, key, state, evidenceValue(value.Value)))
	}
	return joinEvidence(parts, limit)
}

func allMissing(values []ConfigValue) bool {
	for _, value := range values {
		if value.Set {
			return false
		}
	}
	return true
}

type LogSettings struct {
	ErrorLog  string
	AccessLog []string
	MailLog   []string
	Source    string
}

func logSettings(state discoveryState) LogSettings {
	logs := LogSettings{}
	for _, file := range state.INI {
		if value := file.Config.Values["error_log"]; value != "" && logs.ErrorLog == "" {
			logs.ErrorLog = value
			logs.Source = file.Source + "/" + file.Version
		}
	}
	for _, pool := range state.Pools {
		if value := pool.PHPAdminValues["error_log"]; value != "" && logs.ErrorLog == "" {
			logs.ErrorLog = value
			logs.Source = pool.Source + "/" + pool.Pool
		}
		if value := poolValue(pool, "access.log"); value != "" {
			logs.AccessLog = appendUnique(logs.AccessLog, value)
		}
		if value := pool.PHPAdminValues["mail.log"]; value != "" {
			logs.MailLog = appendUnique(logs.MailLog, value)
		}
	}
	return logs
}

func logsEvidence(logs LogSettings, limit int) string {
	parts := []string{
		"error_log=" + evidenceValue(logs.ErrorLog),
		"access.log=" + evidenceValue(strings.Join(limitStrings(logs.AccessLog, 3), ",")),
		"mail.log=" + evidenceValue(strings.Join(limitStrings(logs.MailLog, 3), ",")),
	}
	if logs.Source != "" {
		parts = append(parts, "source="+logs.Source)
	}
	return joinEvidence(parts, limit)
}

type SessionCookieSettings struct {
	Secure   string
	HTTPOnly string
	SameSite string
}

func sessionCookieSecurity(files []INIFile) SessionCookieSettings {
	settings := SessionCookieSettings{Secure: "not_set", HTTPOnly: "not_set", SameSite: "not_set"}
	for _, file := range files {
		if value, ok := file.Config.Values["session.cookie_secure"]; ok && settings.Secure == "not_set" {
			settings.Secure = value
		}
		if value, ok := file.Config.Values["session.cookie_httponly"]; ok && settings.HTTPOnly == "not_set" {
			settings.HTTPOnly = value
		}
		if value, ok := file.Config.Values["session.cookie_samesite"]; ok && settings.SameSite == "not_set" {
			settings.SameSite = value
		}
	}
	return settings
}

func iniValueEvidence(values []INIValue, limit int) string {
	parts := []string{}
	for _, value := range values {
		display := evidenceValue(value.Value)
		if value.Missing {
			display = "missing"
		}
		parts = append(parts, fmt.Sprintf("source=%s/%s/%s %s=%s", value.Source, value.Version, value.SAPI, value.Key, display))
	}
	return joinEvidence(parts, limit)
}

func poolUserEvidence(pools []PoolConfig, limit int) string {
	parts := []string{}
	for _, pool := range pools {
		parts = append(parts, fmt.Sprintf("pool=%s/%s user=%s group=%s source=%s", pool.Version, pool.Pool, evidenceValue(poolValue(pool, "user")), evidenceValue(poolValue(pool, "group")), pool.Source))
	}
	return joinEvidence(parts, limit)
}

func poolSocketEvidence(pools []PoolConfig, limit int) string {
	parts := []string{}
	for _, pool := range pools {
		parts = append(parts, fmt.Sprintf("pool=%s/%s listen=%s listen.mode=%s", pool.Version, pool.Pool, evidenceValue(poolValue(pool, "listen")), evidenceValue(poolValue(pool, "listen.mode"))))
	}
	return joinEvidence(parts, limit)
}

func poolValue(pool PoolConfig, key string) string {
	return strings.TrimSpace(pool.Values[strings.ToLower(key)])
}

func workerPools(pools []PoolConfig) []PoolConfig {
	out := []PoolConfig{}
	for _, pool := range pools {
		name := strings.ToLower(pool.Pool)
		if name == "global" || name == "main" {
			continue
		}
		if poolValue(pool, "user") != "" || poolValue(pool, "group") != "" || poolValue(pool, "pm.max_children") != "" {
			out = append(out, pool)
		}
	}
	return out
}

func pmMaxChildrenTooHigh(value int, totalMem int64) bool {
	if value > 500 {
		return true
	}
	if totalMem <= 0 {
		return false
	}
	ramGiB := totalMem / (1024 * 1024 * 1024)
	if ramGiB < 1 {
		ramGiB = 1
	}
	threshold := int(ramGiB) * 100
	if threshold < 100 {
		threshold = 100
	}
	return value > threshold
}

func memTotalBytes(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("MemTotal not found in %s", path)
}

func socketInTmp(listen string) bool {
	listen = strings.TrimSpace(listen)
	return listen == "/tmp" || strings.HasPrefix(listen, "/tmp/")
}

func listenModeTooWide(mode string) bool {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return false
	}
	mode = strings.TrimPrefix(mode, "0")
	value, err := strconv.ParseInt(mode, 8, 64)
	if err != nil {
		return false
	}
	return value&0007 != 0 || value&0002 != 0
}

func isOff(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "off", "0", "false", "no":
		return true
	default:
		return false
	}
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "on", "true", "yes":
		return true
	default:
		return false
	}
}

func splitCSV(value string) []string {
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func evidenceValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}
	return value
}

func joinEvidence(values []string, limit int) string {
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return strings.Join(out, "; ")
}

func limitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func phpConfigSteps(action string) []string {
	return []string{
		"Identify the active php.ini or PHP-FPM pool file.",
		action,
		"Validate PHP-FPM configuration and reload the relevant php-fpm service.",
	}
}

func ansibleLine(key, value, path string) string {
	return "- name: Configure PHP " + key + "\n  ansible.builtin.lineinfile:\n    path: " + path + "\n    regexp: '^\\s*#?\\s*" + regexp.QuoteMeta(key) + "\\s*='\n    line: '" + key + " = " + value + "'\n  notify: reload php-fpm"
}

func chefLine(key, value, path string) string {
	return "ruby_block 'configure php " + key + "' do\n  block { Chef::Util::FileEdit.new('" + path + "').search_file_replace_line(/^\\s*#?\\s*" + regexp.QuoteMeta(key) + "\\s*=/, '" + key + " = " + value + "').write_file }\nend"
}

func parsePHPVersion(output string) string {
	re := regexp.MustCompile(`(?i)PHP\s+([0-9]+(?:\.[0-9]+){1,2})`)
	matches := re.FindStringSubmatch(output)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func versionFromDirectAdminPath(path string) string {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(part, "php") && len(part) >= 5 && allDigits(part[3:]) {
			digits := part[3:]
			if len(digits) == 2 {
				return digits[:1] + "." + digits[1:]
			}
			if len(digits) == 3 {
				return digits[:1] + "." + digits[1:]
			}
		}
	}
	return "unknown"
}

func versionFromSystemPath(path string) string {
	base := filepath.Base(path)
	re := regexp.MustCompile(`php(?:-fpm)?([0-9]+(?:\.[0-9]+)?)`)
	if matches := re.FindStringSubmatch(base); len(matches) == 2 && matches[1] != "" {
		return matches[1]
	}
	return "unknown"
}

func versionFromPath(path, source string) string {
	if source == sourceDirectAdmin {
		return versionFromDirectAdminPath(path)
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if part == "php" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return versionFromSystemPath(path)
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func poolName(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		return "default"
	}
	return name
}

func uniqueVersions(versions []PHPVersion) []PHPVersion {
	seen := map[string]struct{}{}
	out := []PHPVersion{}
	for _, version := range versions {
		if version.Version == "" {
			version.Version = "unknown"
		}
		key := version.Version + "|" + version.SAPI + "|" + version.SourcePath
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, version)
	}
	return out
}

func sortVersions(versions []PHPVersion) {
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].Version != versions[j].Version {
			return versions[i].Version < versions[j].Version
		}
		if versions[i].SAPI != versions[j].SAPI {
			return versions[i].SAPI < versions[j].SAPI
		}
		return versions[i].SourcePath < versions[j].SourcePath
	})
}

func sortINI(files []INIFile) {
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
}

func sortPools(pools []PoolConfig) {
	sort.SliceStable(pools, func(i, j int) bool {
		if pools[i].Path != pools[j].Path {
			return pools[i].Path < pools[j].Path
		}
		return pools[i].Pool < pools[j].Pool
	})
}

func globAll(patterns []string) []string {
	matches := []string{}
	for _, pattern := range patterns {
		values, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		matches = append(matches, values...)
	}
	sort.Strings(matches)
	return matches
}

func expandGlobs(groups ...[]string) []string {
	paths := []string{}
	for _, group := range groups {
		paths = append(paths, globAll(group)...)
	}
	return paths
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
