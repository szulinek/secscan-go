package redis

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	pathmatch "path"
	"regexp"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "redis"
	service  = "redis"
)

var (
	redisConfigPaths = []string{"/etc/redis/redis.conf", "/etc/redis.conf"}
	redisBinaryPaths = []string{"/usr/bin/redis-server", "/usr/local/bin/redis-server"}
	lookPath         = exec.LookPath
)

type Module struct{}

type configCache struct {
	loaded bool
	path   string
	config Config
	err    error
}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "Redis"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &configCache{}
	return []checks.Check{
		checkVersion{},
		checkBindLocalhost{cache: cache},
		checkProtectedMode{cache: cache},
		checkMaxMemory{cache: cache},
		checkPersistence{cache: cache},
		checkAuthentication{cache: cache},
	}
}

type checkVersion struct{}

func (c checkVersion) ID() string {
	return "redis.version"
}

func (c checkVersion) Title() string {
	return "Redis version"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Redis version was collected."
	result.ClientSummary = "Redis version information was recorded."
	result.AdminDetails = "Collected Redis version from redis-server --version, falling back to redis-cli INFO server."
	result.Impact = "Redis version inventory helps prioritize patching and lifecycle decisions."
	result.Recommendation = "Keep Redis on a supported, patched release."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "redis-server --version; redis-cli INFO server | grep '^redis_version:'"}
	result.HiddenInClientReport = true

	if !ensureRedisDetected(ctx, &result, "Redis version check") {
		return result
	}

	version, source, err := redisVersion(ctx)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Redis version could not be collected."
		result.ClientSummary = "Redis version could not be verified."
		result.AdminDetails = "Both redis-server --version and redis-cli INFO server failed.\n" + err.Error()
		result.Evidence = "version=unknown command_error=true"
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	result.Evidence = "version=" + version + " source=" + source
	return result
}

type checkBindLocalhost struct {
	cache *configCache
}

func (c checkBindLocalhost) ID() string {
	return "redis.bind_localhost"
}

func (c checkBindLocalhost) Title() string {
	return "Redis bind address is restricted"
}

func (c checkBindLocalhost) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Redis bind address is restricted to localhost or private interfaces."
	result.ClientSummary = "Redis network binding is restricted."
	result.AdminDetails = "Parsed bind directives from redis.conf."
	result.Impact = "Redis exposed to public interfaces can be abused for unauthorized data access, service disruption, or lateral movement."
	result.Recommendation = "Restrict Redis to localhost/private interfaces."
	result.Remediation = result.Recommendation
	result.RemediationSteps = redisConfigSteps("Set bind to 127.0.0.1 or private application interfaces only.")
	result.Automation = checks.Automation{
		Shell:   "grep -E '^\\s*bind\\b' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null",
		Ansible: ansibleLine("bind 127.0.0.1"),
		Chef:    chefLine("bind 127.0.0.1"),
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "bind address check")
	if !ok {
		return result
	}

	binds := redisBindValues(config)
	result.Evidence = "bind=" + bindEvidence(binds)
	assessment := assessBind(binds)
	switch assessment {
	case bindMissing:
		result.Title = "Redis bind address is not explicit"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Redis bind directive is not configured."
		result.ClientSummary = "Redis bind address is not explicit."
	case bindPublic:
		result.Title = "Redis may bind to a public interface"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Redis bind directive includes a public or wildcard interface."
		result.ClientSummary = "Redis appears publicly reachable."
	}
	return result
}

type checkProtectedMode struct {
	cache *configCache
}

func (c checkProtectedMode) ID() string {
	return "redis.protected_mode"
}

func (c checkProtectedMode) Title() string {
	return "Redis protected mode is enabled"
}

func (c checkProtectedMode) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Redis protected mode is enabled."
	result.ClientSummary = "Redis protected mode is enabled."
	result.AdminDetails = "Parsed protected-mode from redis.conf."
	result.Impact = "Protected mode helps prevent accidental unauthenticated access from non-local interfaces."
	result.Recommendation = "Keep protected-mode enabled unless Redis is explicitly secured by binding, firewalling, and authentication."
	result.Remediation = result.Recommendation
	result.RemediationSteps = redisConfigSteps("Set protected-mode yes.")
	result.Automation = checks.Automation{
		Shell:   "grep -E '^\\s*protected-mode\\b' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null",
		Ansible: ansibleLine("protected-mode yes"),
		Chef:    chefLine("protected-mode yes"),
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "protected-mode check")
	if !ok {
		return result
	}

	value := directiveFirstValue(config, "protected-mode", "default(yes)")
	result.Evidence = "protected-mode=" + value
	if strings.EqualFold(value, "no") {
		result.Title = "Redis protected mode is disabled"
		result.Status = checks.StatusWarn
		result.Summary = "Redis protected-mode is set to no."
		result.ClientSummary = "Redis protected mode is disabled."
	}
	return result
}

type checkMaxMemory struct {
	cache *configCache
}

func (c checkMaxMemory) ID() string {
	return "redis.maxmemory"
}

func (c checkMaxMemory) Title() string {
	return "Redis maxmemory is configured"
}

func (c checkMaxMemory) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Redis maxmemory is configured."
	result.ClientSummary = "Redis memory limit is configured."
	result.AdminDetails = "Parsed maxmemory from redis.conf."
	result.Impact = "Redis without a memory limit can consume host memory and affect colocated services."
	result.Recommendation = "Configure memory limits to avoid host exhaustion."
	result.Remediation = result.Recommendation
	result.RemediationSteps = redisConfigSteps("Set maxmemory to an application-appropriate non-zero value.")
	result.Automation = checks.Automation{
		Shell:   "grep -E '^\\s*maxmemory\\b' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null",
		Ansible: ansibleLine("maxmemory 512mb"),
		Chef:    chefLine("maxmemory 512mb"),
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "maxmemory check")
	if !ok {
		return result
	}

	value := directiveFirstValue(config, "maxmemory", "not_set")
	result.Evidence = "maxmemory=" + value
	if value == "not_set" || maxMemoryIsZero(value) {
		result.Title = "Redis maxmemory is not configured"
		result.Status = checks.StatusWarn
		result.Summary = "Redis maxmemory is missing or set to zero."
		result.ClientSummary = "Redis memory limit is not configured."
	}
	return result
}

type checkPersistence struct {
	cache *configCache
}

func (c checkPersistence) ID() string {
	return "redis.persistence"
}

func (c checkPersistence) Title() string {
	return "Redis persistence is configured"
}

func (c checkPersistence) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Redis persistence is configured."
	result.ClientSummary = "Redis persistence is configured."
	result.AdminDetails = "Parsed appendonly and save directives from redis.conf."
	result.Impact = "Without persistence, Redis data can be lost after restarts, crashes, or host maintenance."
	result.Recommendation = "Enable appendonly or configure snapshot save directives according to data durability requirements."
	result.Remediation = result.Recommendation
	result.RemediationSteps = redisConfigSteps("Enable appendonly yes or configure save snapshot directives.")
	result.Automation = checks.Automation{
		Shell:   "grep -E '^\\s*(appendonly|save)\\b' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null",
		Ansible: ansibleLine("appendonly yes"),
		Chef:    chefLine("appendonly yes"),
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "persistence check")
	if !ok {
		return result
	}

	appendOnly := directiveFirstValue(config, "appendonly", "no")
	save := saveEvidence(config)
	result.Evidence = "appendonly=" + appendOnly + "; save=" + save
	if !strings.EqualFold(appendOnly, "yes") && !hasSaveSnapshots(config) {
		result.Title = "Redis persistence is not configured"
		result.Status = checks.StatusWarn
		result.Summary = "Redis appendonly is disabled and no active save snapshots were found."
		result.ClientSummary = "Redis persistence is not configured."
	}
	return result
}

type checkAuthentication struct {
	cache *configCache
}

func (c checkAuthentication) ID() string {
	return "redis.authentication"
}

func (c checkAuthentication) Title() string {
	return "Redis authentication is configured"
}

func (c checkAuthentication) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Redis authentication is configured."
	result.ClientSummary = "Redis authentication is configured."
	result.AdminDetails = "Parsed requirepass and ACL user directives from redis.conf without exposing secrets."
	result.Impact = "Unauthenticated Redis access can expose data and allow destructive or administrative commands to unauthorized users."
	result.Recommendation = "Enable requirepass or ACL authentication."
	result.Remediation = result.Recommendation
	result.RemediationSteps = redisConfigSteps("Configure requirepass or Redis ACL users with strong secrets.")
	result.Automation = checks.Automation{
		Shell:   "awk 'tolower($1)==\"requirepass\"{print \"requirepass set\"} tolower($1)==\"user\"{print \"acl user configured\"}' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null",
		Ansible: ansibleLine("requirepass {{ redis_requirepass }}"),
		Chef:    chefLine("requirepass CHANGE_ME"),
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "authentication check")
	if !ok {
		return result
	}

	requirePass := requirePassSet(config)
	acl := aclEnabled(config)
	result.Evidence = fmt.Sprintf("requirepass=%s; acl=%s", setEvidence(requirePass), enabledEvidence(acl))
	if requirePass || acl {
		return result
	}

	result.Title = "Redis authentication is not configured"
	result.Status = checks.StatusWarn
	result.Severity = checks.SeverityHigh
	result.Summary = "Redis requirepass is not set and no ACL users were found."
	result.ClientSummary = "Redis authentication is not configured."
	if assessBind(redisBindValues(config)) == bindPublic {
		result.Severity = checks.SeverityCritical
		result.Summary = "Redis is publicly bound and authentication is not configured."
	}
	return result
}

func newResult(id, title string, severity checks.Severity, status checks.Status) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, severity, status)
	result.Category = checks.CategoryCache
	return result
}

func detect(ctx checks.Context) (bool, string) {
	if !linuxTarget(ctx) {
		return false, "detected=false goos=" + ctx.Host.GOOS
	}

	for _, svc := range ctx.Services {
		unit := strings.ToLower(svc.Unit)
		if unit == "redis.service" || unit == "redis-server.service" {
			return true, "running_service=" + svc.Unit
		}
		if matched, err := pathmatch.Match("redis*.service", unit); err == nil && matched {
			return true, "running_service=" + svc.Unit
		}
	}

	if ctx.Runner != nil {
		if output, err := ctx.Runner.Run(ctx.Context, "pgrep", "-x", "redis-server"); err == nil && strings.TrimSpace(string(output)) != "" {
			return true, "process=redis-server"
		}
	}

	if lookPath != nil {
		if path, err := lookPath("redis-cli"); err == nil && path != "" {
			return true, "binary=" + path
		}
	}
	if path, ok := firstExistingPath(redisBinaryPaths); ok {
		return true, "binary=" + path
	}
	if path, ok := firstExistingPath(redisConfigPaths); ok {
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

func ensureRedisDetected(ctx checks.Context, result *checks.Result, checkName string) bool {
	detected, evidence := detect(ctx)
	if detected {
		return true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Redis was not detected; " + checkName + " was skipped."
	result.ClientSummary = "Redis was not detected."
	result.AdminDetails = "This check requires Redis to be installed or running."
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return false
}

func (c *configCache) load() (string, Config, error) {
	if c == nil {
		return loadConfig()
	}
	if !c.loaded {
		c.path, c.config, c.err = loadConfig()
		c.loaded = true
	}
	return c.path, c.config, c.err
}

func loadConfig() (string, Config, error) {
	path, ok := firstExistingPath(redisConfigPaths)
	if !ok {
		return "", Config{}, os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return path, Config{}, err
	}
	return path, ParseConfig(string(data)), nil
}

func loadConfigForResult(ctx checks.Context, cache *configCache, result *checks.Result, checkName string) (Config, bool) {
	if !ensureRedisDetected(ctx, result, checkName) {
		return Config{}, false
	}

	path, config, err := cache.load()
	if err == nil {
		result.AdminDetails += "\nConfig path: " + path
		return config, true
	}
	if errors.Is(err, os.ErrNotExist) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Redis configuration file was not found; " + checkName + " was skipped."
		result.ClientSummary = "Redis configuration could not be found."
		result.AdminDetails = "Checked Redis configuration paths: " + strings.Join(redisConfigPaths, ", ")
		result.Evidence = "redis_conf=not_found"
		result.HiddenInClientReport = true
		return Config{}, false
	}

	result.Status = checks.StatusError
	result.Severity = checks.SeverityMedium
	result.Summary = "Redis configuration file could not be read."
	result.ClientSummary = "Redis configuration could not be verified."
	result.AdminDetails = "Read failed for Redis configuration.\n" + err.Error()
	result.Evidence = "redis_conf=read_error path=" + path
	result.Error = err.Error()
	result.HiddenInClientReport = true
	return Config{}, false
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func redisVersion(ctx checks.Context) (string, string, error) {
	output, serverErr := ctx.Runner.Run(ctx.Context, "redis-server", "--version")
	if serverErr == nil {
		if version := parseRedisServerVersion(string(output)); version != "" {
			return version, "redis-server", nil
		}
		serverErr = fmt.Errorf("redis-server --version output did not contain a version")
	}

	output, cliErr := ctx.Runner.Run(ctx.Context, "redis-cli", "INFO", "server")
	if cliErr == nil {
		if version := parseRedisInfoVersion(string(output)); version != "" {
			return version, "redis-cli", nil
		}
		cliErr = fmt.Errorf("redis-cli INFO server output did not contain redis_version")
	}

	return "", "", fmt.Errorf("redis-server --version: %v; redis-cli INFO server: %v", serverErr, cliErr)
}

var redisVersionRE = regexp.MustCompile(`(?:v=|redis_version:)([0-9]+(?:\.[0-9]+){1,3})`)

func parseRedisServerVersion(output string) string {
	matches := redisVersionRE.FindStringSubmatch(output)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func parseRedisInfoVersion(output string) string {
	matches := redisVersionRE.FindStringSubmatch(output)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func directiveFirstValue(config Config, key, missing string) string {
	directive, ok := config.LastValue(key)
	if !ok || len(directive.Values) == 0 {
		return missing
	}
	value := strings.TrimSpace(directive.Values[0])
	if value == "" {
		return missing
	}
	return value
}

func redisBindValues(config Config) []string {
	values := []string{}
	for _, directive := range config.Values("bind") {
		values = append(values, directive.Values...)
	}
	return values
}

type bindAssessment int

const (
	bindRestricted bindAssessment = iota
	bindMissing
	bindPublic
)

func assessBind(values []string) bindAssessment {
	if len(values) == 0 {
		return bindMissing
	}
	for _, value := range values {
		if !isRestrictedBind(value) {
			return bindPublic
		}
	}
	return bindRestricted
}

func isRestrictedBind(value string) bool {
	value = strings.TrimSpace(strings.TrimPrefix(value, "-"))
	value = strings.Trim(value, "[]")
	if value == "" {
		return false
	}
	if strings.EqualFold(value, "localhost") {
		return true
	}
	if value == "*" || value == "0.0.0.0" || value == "::" || value == "::0" || value == "::/0" {
		return false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func bindEvidence(values []string) string {
	if len(values) == 0 {
		return "not_set"
	}
	return strings.Join(values, ",")
}

func maxMemoryIsZero(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "0" || value == "0b" || value == "0kb" || value == "0mb" || value == "0gb"
}

func saveEvidence(config Config) string {
	save := activeSaveDirectives(config)
	if len(save) == 0 {
		return "none"
	}
	return strings.Join(save, "|")
}

func hasSaveSnapshots(config Config) bool {
	return len(activeSaveDirectives(config)) > 0
}

func activeSaveDirectives(config Config) []string {
	save := []string{}
	for _, directive := range config.Values("save") {
		if len(directive.Values) == 0 {
			continue
		}
		if len(directive.Values) == 1 && strings.TrimSpace(directive.Values[0]) == "" {
			continue
		}
		if len(directive.Values) == 1 && directive.Values[0] == `""` {
			continue
		}
		if len(directive.Values) == 1 && directive.Values[0] == "" {
			continue
		}
		save = append(save, strings.Join(directive.Values, " "))
	}
	return save
}

func requirePassSet(config Config) bool {
	directive, ok := config.LastValue("requirepass")
	return ok && len(directive.Values) > 0 && strings.TrimSpace(directive.Values[0]) != ""
}

func aclEnabled(config Config) bool {
	for _, directive := range config.Values("user") {
		if len(directive.Values) > 0 {
			return true
		}
	}
	return false
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

func redisConfigSteps(action string) []string {
	return []string{
		"Edit the active redis.conf file.",
		action,
		"Validate the configuration and restart Redis during an approved maintenance window.",
	}
}

func ansibleLine(line string) string {
	parts := strings.Fields(line)
	regexp := "^\\s*#?\\s*" + parts[0] + "\\b"
	return "- name: Configure Redis " + parts[0] + "\n  ansible.builtin.lineinfile:\n    path: /etc/redis/redis.conf\n    regexp: '" + regexp + "'\n    line: '" + line + "'\n  notify: restart redis"
}

func chefLine(line string) string {
	parts := strings.Fields(line)
	return "ruby_block 'configure redis " + parts[0] + "' do\n  block { Chef::Util::FileEdit.new('/etc/redis/redis.conf').search_file_replace_line(/^\\s*#?\\s*" + parts[0] + "\\b/, '" + line + "').write_file }\nend"
}
