package phpfpm

import (
	"fmt"
	"os"
	pathmatch "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "php_fpm"
	service  = "php-fpm"
)

var (
	phpFPMBinaryGlobs = []string{"/usr/local/php*/sbin/php-fpm", "/usr/sbin/php-fpm*"}
	phpFPMDetectPaths = []string{"/usr/sbin/php-fpm", "/usr/local/php/sbin/php-fpm"}
	phpFPMDetectGlobs = []string{"/usr/local/php*/sbin/php-fpm", "/usr/local/php*/etc/php-fpm.conf", "/usr/local/php*/etc/php-fpm.d/*.conf", "/etc/php/*/fpm/php-fpm.conf"}
)

type Module struct{}

type discoveryCache struct {
	loaded        bool
	installations []installation
}

type installation struct {
	Version  string
	Binary   string
	INI      string
	PoolGlob string
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
		checkVersion{cache: cache},
		checkExposePHP{cache: cache},
		checkDisplayErrors{cache: cache},
		checkDisableFunctions{cache: cache},
		checkCGIFixPathInfo{cache: cache},
		checkPoolUser{cache: cache},
		checkPMMaxChildren{cache: cache},
	}
}

type checkVersion struct {
	cache *discoveryCache
}

func (c checkVersion) ID() string {
	return "php_fpm.version"
}

func (c checkVersion) Title() string {
	return "PHP-FPM versions detected"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Impact = "PHP-FPM version inventory helps plan patching and migration work."
	result.Recommendation = "Keep all PHP-FPM versions supported and patched."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP-FPM versions were inventoried."
	result.AdminDetails = "Discovered PHP-FPM binaries from configured binary globs."
	result.HiddenInClientReport = true

	installations := c.cache.load()
	if len(installations) == 0 {
		result.Summary = "No PHP-FPM binaries were found."
		result.Evidence = "php_fpm_binaries=not_found"
		return result
	}

	result.Summary = "PHP-FPM binaries were found."
	result.Evidence = installationsEvidence(installations)
	return result
}

type checkExposePHP struct {
	cache *discoveryCache
}

func (c checkExposePHP) ID() string {
	return "php_fpm.expose_php"
}

func (c checkExposePHP) Title() string {
	return "expose_php is disabled"
}

func (c checkExposePHP) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Impact = "PHP version disclosure makes fingerprinting easier for automated scanners."
	result.Recommendation = "Set expose_php = Off in every active PHP-FPM php.ini."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP version disclosure is disabled."
	result.AdminDetails = "Checked expose_php in php.ini for discovered PHP-FPM installations."
	result.RemediationSteps = []string{
		"Edit php.ini for every active PHP-FPM version.",
		"Set expose_php = Off.",
		"Reload the relevant PHP-FPM service.",
	}
	result.References = []string{
		"https://www.php.net/manual/en/ini.core.php#ini.expose-php",
		"https://www.debian.org/doc/manuals/securing-debian-manual/",
		"https://www.cisecurity.org/benchmark/debian_linux",
	}
	result.Automation = checks.Automation{
		Shell:   "sudo sed -i 's/^\\s*expose_php\\s*=.*/expose_php = Off/' /usr/local/php*/lib/php.ini && sudo systemctl reload 'php*-fpm.service'",
		Ansible: "- name: Disable expose_php\n  ansible.builtin.lineinfile:\n    path: '{{ php_ini_path }}'\n    regexp: '^\\s*expose_php\\s*='\n    line: 'expose_php = Off'\n  notify: reload php-fpm",
		Chef:    "ruby_block 'disable expose_php' do\n  block { Chef::Util::FileEdit.new('/usr/local/php/lib/php.ini').search_file_replace_line(/^\\s*expose_php\\s*=/, 'expose_php = Off').write_file }\nend",
	}

	values := iniDirectiveValues(c.cache.load(), "expose_php", "On")
	return applyINIExpectation(result, values, "expose_php", func(value string) bool {
		return isOff(value)
	}, "expose_php is enabled", "PHP version disclosure is enabled.")
}

type checkDisplayErrors struct {
	cache *discoveryCache
}

func (c checkDisplayErrors) ID() string {
	return "php_fpm.display_errors"
}

func (c checkDisplayErrors) Title() string {
	return "display_errors is disabled"
}

func (c checkDisplayErrors) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Impact = "Displayed PHP errors can leak filesystem paths, SQL details, and application internals."
	result.Recommendation = "Set display_errors = Off in production PHP-FPM php.ini files."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP runtime errors are not displayed to visitors."
	result.AdminDetails = "Checked display_errors in php.ini for discovered PHP-FPM installations."

	values := iniDirectiveValues(c.cache.load(), "display_errors", "On")
	return applyINIExpectation(result, values, "display_errors", func(value string) bool {
		return isOff(value)
	}, "display_errors is enabled", "PHP errors may be shown to visitors.")
}

type checkDisableFunctions struct {
	cache *discoveryCache
}

func (c checkDisableFunctions) ID() string {
	return "php_fpm.disable_functions"
}

func (c checkDisableFunctions) Title() string {
	return "disable_functions is configured"
}

func (c checkDisableFunctions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Impact = "A broad PHP function surface can increase post-exploitation options for vulnerable applications."
	result.Recommendation = "Configure disable_functions according to application compatibility and hosting policy."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP dangerous-function restrictions are configured."
	result.AdminDetails = "Checked disable_functions in php.ini for discovered PHP-FPM installations."

	values := iniDirectiveValues(c.cache.load(), "disable_functions", "")
	if len(values) == 0 {
		return notApplicable(result, "php_ini=not_found", "No PHP-FPM php.ini files were found.")
	}

	issues := []iniValue{}
	for _, value := range values {
		if strings.TrimSpace(value.Value) == "" {
			issues = append(issues, value)
		}
	}
	result.Evidence = iniEvidence(values)
	if len(issues) > 0 {
		result.Title = "disable_functions is empty"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP-FPM versions have empty disable_functions."
		result.ClientSummary = "PHP dangerous-function restrictions are not configured everywhere."
		result.Evidence = iniEvidence(issues)
		return result
	}

	result.Summary = "disable_functions is configured for discovered PHP-FPM versions."
	return result
}

type checkCGIFixPathInfo struct {
	cache *discoveryCache
}

func (c checkCGIFixPathInfo) ID() string {
	return "php_fpm.cgi_fix_pathinfo"
}

func (c checkCGIFixPathInfo) Title() string {
	return "cgi.fix_pathinfo is disabled"
}

func (c checkCGIFixPathInfo) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Impact = "cgi.fix_pathinfo can increase risk from unsafe Nginx/PHP path handling combinations."
	result.Recommendation = "Set cgi.fix_pathinfo = 0 in every active PHP-FPM php.ini."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP path info handling is hardened."
	result.AdminDetails = "Checked cgi.fix_pathinfo in php.ini for discovered PHP-FPM installations."

	values := iniDirectiveValues(c.cache.load(), "cgi.fix_pathinfo", "1")
	return applyINIExpectation(result, values, "cgi.fix_pathinfo", func(value string) bool {
		return strings.TrimSpace(value) == "0"
	}, "cgi.fix_pathinfo is enabled or missing", "PHP path info handling should be hardened.")
}

type checkPoolUser struct {
	cache *discoveryCache
}

func (c checkPoolUser) ID() string {
	return "php_fpm.pool_user"
}

func (c checkPoolUser) Title() string {
	return "PHP-FPM pools do not run as root"
}

func (c checkPoolUser) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Impact = "A PHP-FPM pool running as root can turn an application compromise into full host compromise."
	result.Recommendation = "Run PHP-FPM pools as dedicated unprivileged users, never root."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP-FPM pools do not run as root."
	result.AdminDetails = "Parsed PHP-FPM pool configuration files and checked user directives."

	pools, readErrors := poolConfigs(c.cache.load())
	if len(readErrors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "PHP-FPM pool configuration could not be read."
		result.ClientSummary = "PHP-FPM pool users could not be verified."
		result.Evidence = strings.Join(readErrors, "; ")
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return result
	}
	if len(pools) == 0 {
		return notApplicable(result, "pools=not_found", "No PHP-FPM pool configuration files were found.")
	}

	missing := []poolConfig{}
	rootPools := []poolConfig{}
	for _, pool := range pools {
		if strings.TrimSpace(pool.User) == "" {
			missing = append(missing, pool)
			continue
		}
		if pool.User == "root" {
			rootPools = append(rootPools, pool)
		}
	}

	result.Evidence = poolUserEvidence(pools)
	if len(rootPools) > 0 {
		result.Title = "PHP-FPM pool runs as root"
		result.Status = checks.StatusFail
		result.Summary = "One or more PHP-FPM pools are configured to run as root."
		result.ClientSummary = "A PHP-FPM pool is running with root privileges."
		result.Evidence = poolUserEvidence(rootPools)
		return result
	}
	if len(missing) > 0 {
		result.Title = "PHP-FPM pool user is not explicit"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP-FPM pools do not define an explicit user."
		result.ClientSummary = "Some PHP-FPM pool users need administrator review."
		result.Evidence = poolUserEvidence(missing)
		return result
	}

	result.Summary = "No PHP-FPM pool is configured to run as root."
	return result
}

type checkPMMaxChildren struct {
	cache *discoveryCache
}

func (c checkPMMaxChildren) ID() string {
	return "php_fpm.pm_max_children"
}

func (c checkPMMaxChildren) Title() string {
	return "pm.max_children is configured"
}

func (c checkPMMaxChildren) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Impact = "Unbounded or very high PHP-FPM worker limits can exhaust host memory under load."
	result.Recommendation = "Set pm.max_children per pool based on available memory and workload."
	result.Remediation = result.Recommendation
	result.ClientSummary = "PHP-FPM worker limits are configured."
	result.AdminDetails = "Parsed PHP-FPM pool configuration files and checked pm.max_children values."

	pools, readErrors := poolConfigs(c.cache.load())
	if len(readErrors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "PHP-FPM pool configuration could not be read."
		result.ClientSummary = "PHP-FPM worker limits could not be verified."
		result.Evidence = strings.Join(readErrors, "; ")
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return result
	}
	if len(pools) == 0 {
		return notApplicable(result, "pools=not_found", "No PHP-FPM pool configuration files were found.")
	}

	issues := []poolConfig{}
	for _, pool := range pools {
		if pool.PMMaxChildren == "" {
			issues = append(issues, pool)
			continue
		}
		value, err := strconv.Atoi(pool.PMMaxChildren)
		if err != nil || value <= 0 || value > 500 {
			issues = append(issues, pool)
		}
	}

	result.Evidence = pmMaxChildrenEvidence(pools)
	if len(issues) > 0 {
		result.Title = "pm.max_children needs review"
		result.Status = checks.StatusWarn
		result.Summary = "One or more PHP-FPM pools are missing pm.max_children or use a very high value."
		result.ClientSummary = "Some PHP-FPM worker limits need administrator review."
		result.Evidence = pmMaxChildrenEvidence(issues)
		return result
	}

	result.Summary = "PHP-FPM pm.max_children values look reasonable."
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

	if path, ok := firstExistingPath(phpFPMDetectPaths); ok {
		return true, "path_exists=" + path
	}
	if path, ok := firstGlobMatch(phpFPMDetectGlobs); ok {
		return true, "path_exists=" + path
	}
	return false, "detected=false"
}

func (c *discoveryCache) load() []installation {
	if c == nil {
		return discoverInstallations()
	}
	if !c.loaded {
		c.installations = discoverInstallations()
		c.loaded = true
	}
	return c.installations
}

func discoverInstallations() []installation {
	binaries := globAll(phpFPMBinaryGlobs)
	installations := []installation{}
	seen := map[string]struct{}{}
	for _, binary := range binaries {
		if _, ok := seen[binary]; ok {
			continue
		}
		seen[binary] = struct{}{}
		installations = append(installations, installationFromBinary(binary))
	}

	sort.SliceStable(installations, func(i, j int) bool {
		return installations[i].Version < installations[j].Version
	})
	return installations
}

func installationFromBinary(binary string) installation {
	root := filepath.Dir(filepath.Dir(binary))
	version := filepath.Base(root)
	if version == "." || version == string(filepath.Separator) || version == "" {
		version = filepath.Base(binary)
	}

	return installation{
		Version:  version,
		Binary:   binary,
		INI:      filepath.Join(root, "lib", "php.ini"),
		PoolGlob: filepath.Join(root, "etc", "php-fpm.d", "*.conf"),
	}
}

func installationsEvidence(installations []installation) string {
	if len(installations) == 0 {
		return "php_fpm_binaries=not_found"
	}

	values := []string{}
	for _, install := range installations {
		values = append(values, install.Version+"="+install.Binary)
	}
	return strings.Join(values, "; ")
}

type iniValue struct {
	Version string
	Path    string
	Key     string
	Value   string
	Missing bool
}

func iniDirectiveValues(installations []installation, key, missingDefault string) []iniValue {
	values := []iniValue{}
	for _, install := range installations {
		data, err := os.ReadFile(install.INI)
		if err != nil {
			continue
		}
		parsed := parseKeyValues(string(data))
		value, ok := parsed[strings.ToLower(key)]
		missing := false
		if !ok {
			value = missingDefault
			missing = true
		}
		values = append(values, iniValue{
			Version: install.Version,
			Path:    install.INI,
			Key:     key,
			Value:   value,
			Missing: missing,
		})
	}
	return values
}

func applyINIExpectation(result checks.Result, values []iniValue, key string, pass func(string) bool, issueTitle, issueClientSummary string) checks.Result {
	if len(values) == 0 {
		return notApplicable(result, "php_ini=not_found", "No PHP-FPM php.ini files were found.")
	}

	issues := []iniValue{}
	for _, value := range values {
		if !pass(value.Value) {
			issues = append(issues, value)
		}
	}

	result.Evidence = iniEvidence(values)
	if len(issues) > 0 {
		result.Title = issueTitle
		result.Status = checks.StatusWarn
		result.Summary = key + " is not hardened for one or more PHP-FPM versions."
		result.ClientSummary = issueClientSummary
		result.Evidence = iniEvidence(issues)
		return result
	}

	result.Summary = key + " is hardened for discovered PHP-FPM versions."
	return result
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

func iniEvidence(values []iniValue) string {
	parts := []string{}
	for _, value := range values {
		evidence := evidenceValue(value.Value)
		if value.Missing {
			evidence = "missing(default " + evidence + ")"
		}
		parts = append(parts, fmt.Sprintf("%s:%s=%s", value.Version, value.Key, evidence))
	}
	return strings.Join(parts, "; ")
}

func evidenceValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}
	return value
}

func isOff(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "off", "0", "false", "no":
		return true
	default:
		return false
	}
}

type poolConfig struct {
	Version       string
	Path          string
	Pool          string
	User          string
	PMMaxChildren string
}

func poolConfigs(installations []installation) ([]poolConfig, []string) {
	pools := []poolConfig{}
	readErrors := []string{}
	for _, install := range installations {
		matches, err := filepath.Glob(install.PoolGlob)
		if err != nil {
			readErrors = append(readErrors, install.Version+":pool_glob_error")
			continue
		}
		sort.Strings(matches)
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				readErrors = append(readErrors, install.Version+":"+filepath.Base(path)+"=read_error")
				continue
			}
			pools = append(pools, parsePoolConfig(install.Version, path, string(data))...)
		}
	}
	return pools, readErrors
}

func parsePoolConfig(version, path, content string) []poolConfig {
	pool := poolConfig{Version: version, Path: path, Pool: poolName(path)}
	pools := []poolConfig{}
	hasSection := false
	for _, line := range strings.Split(content, "\n") {
		line = stripConfigComment(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			if hasSection || pool.User != "" || pool.PMMaxChildren != "" {
				pools = append(pools, pool)
			}
			pool = poolConfig{Version: version, Path: path, Pool: strings.TrimSpace(line[1:strings.Index(line, "]")])}
			hasSection = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "user":
			pool.User = strings.TrimSpace(value)
		case "pm.max_children":
			pool.PMMaxChildren = strings.TrimSpace(value)
		}
	}
	if hasSection || pool.User != "" || pool.PMMaxChildren != "" {
		pools = append(pools, pool)
	}
	return pools
}

func poolName(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		return "default"
	}
	return name
}

func poolUserEvidence(pools []poolConfig) string {
	values := []string{}
	for _, pool := range pools {
		user := evidenceValue(pool.User)
		values = append(values, fmt.Sprintf("%s/%s:user=%s", pool.Version, pool.Pool, user))
	}
	return strings.Join(values, "; ")
}

func pmMaxChildrenEvidence(pools []poolConfig) string {
	values := []string{}
	for _, pool := range pools {
		value := evidenceValue(pool.PMMaxChildren)
		values = append(values, fmt.Sprintf("%s/%s:pm.max_children=%s", pool.Version, pool.Pool, value))
	}
	return strings.Join(values, "; ")
}

func parseKeyValues(content string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = stripConfigComment(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values
}

func stripConfigComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
		return ""
	}
	for _, marker := range []string{";", "#"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			line = line[:idx]
		}
	}
	return strings.TrimSpace(line)
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

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func firstGlobMatch(patterns []string) (string, bool) {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		return matches[0], true
	}
	return "", false
}
