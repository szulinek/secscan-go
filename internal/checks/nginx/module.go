package nginx

import (
	"os"
	"regexp"
	"sort"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "nginx"
	service  = "nginx"
)

type Module struct{}

type configCache struct {
	loaded bool
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
	return "Nginx"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &configCache{}
	return []checks.Check{
		checkServiceDetected{},
		checkServerTokens{cache: cache},
		checkAutoindex{cache: cache},
		checkHiddenFilesAccess{cache: cache},
		checkDirectoryListingRisk{cache: cache},
		checkTLSProtocols{cache: cache},
		checkSecurityHeaders{cache: cache},
		checkDefaultVhost{cache: cache},
	}
}

type checkServiceDetected struct{}

func (c checkServiceDetected) ID() string {
	return "nginx.service_detected"
}

func (c checkServiceDetected) Title() string {
	return "Service detected"
}

func (c checkServiceDetected) Run(ctx checks.Context) checks.Result {
	detected, evidence := detect(ctx)
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategoryWeb
	result.Evidence = evidence
	result.Impact = "Inventory signal only; this does not indicate a security problem by itself."
	result.Recommendation = "Run web-server security checks for TLS, headers, exposed status endpoints, and hardening options."
	result.Remediation = result.Recommendation
	result.HiddenInClientReport = true

	if detected {
		result.Summary = "Nginx was detected."
		result.ClientSummary = "Nginx is present on the server."
		result.AdminDetails = "Detection evidence: " + evidence
		return result
	}

	result.Summary = "Nginx was not detected."
	result.ClientSummary = "Nginx was not detected."
	result.AdminDetails = "No nginx systemd unit or known nginx path was found."
	return result
}

type checkServerTokens struct {
	cache *configCache
}

func (c checkServerTokens) ID() string {
	return "nginx.server_tokens"
}

func (c checkServerTokens) Title() string {
	return "server_tokens is disabled"
}

func (c checkServerTokens) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityLow, checks.StatusWarn)
	result.Category = checks.CategoryWeb
	result.Impact = "Version disclosure makes fingerprinting easier for automated scanners and opportunistic attackers."
	result.Recommendation = "Set server_tokens off; in the nginx http/server context and reload nginx."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Nginx may expose version information."
	result.AdminDetails = "Checked effective nginx configuration using nginx -T."
	result.RemediationSteps = []string{
		"Edit nginx.conf or the included server configuration.",
		"Set server_tokens off in the http context.",
		"Validate with nginx -t and reload nginx.",
	}
	result.References = []string{
		"https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
		"https://www.cisecurity.org/benchmark/nginx",
	}
	result.Automation = checks.Automation{
		Shell:   "sudo sed -i 's/^#\\?\\s*server_tokens.*/server_tokens off;/' /etc/nginx/nginx.conf && sudo nginx -t && sudo systemctl reload nginx",
		Ansible: "- name: Disable nginx server tokens\n  ansible.builtin.lineinfile:\n    path: /etc/nginx/nginx.conf\n    regexp: '^\\s*#?\\s*server_tokens'\n    line: 'server_tokens off;'\n  notify: reload nginx",
		Chef:    "template '/etc/nginx/nginx.conf' do\n  notifies :reload, 'service[nginx]'\nend",
	}

	config, ok := loadConfigForResult(ctx, c.cache, &result, "server_tokens check")
	if !ok {
		return result
	}

	setting := serverTokensSettingFromConfig(config)
	result.Evidence = "server_tokens=" + setting

	if setting == "off" {
		result.Status = checks.StatusPass
		result.Title = "server_tokens is disabled"
		result.Summary = "Nginx server_tokens is disabled."
		result.ClientSummary = "Nginx version disclosure is disabled."
		return result
	}

	result.Title = "server_tokens is enabled"
	if setting == "on" {
		result.Summary = "Nginx server_tokens is explicitly enabled."
		return result
	}

	result.Summary = "Nginx server_tokens was not set to off; nginx defaults to exposing version tokens."
	result.Evidence = "server_tokens=default(on)"
	return result
}

type checkAutoindex struct {
	cache *configCache
}

func (c checkAutoindex) ID() string {
	return "nginx.autoindex"
}

func (c checkAutoindex) Title() string {
	return "autoindex is disabled"
}

func (c checkAutoindex) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "Directory listings can expose application files, backups, logs, and deployment artifacts."
	result.Recommendation = "Set autoindex off or remove the directive from public server/location contexts."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Directory listing is not enabled in the effective Nginx configuration."
	result.AdminDetails = "Checked nginx -T output for autoindex on directives."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "autoindex check")
	if !ok {
		return result
	}

	evidence := autoindexOnEvidence(config)
	if len(evidence) > 0 {
		result.Title = "autoindex is enabled"
		result.Status = checks.StatusWarn
		result.Summary = "Nginx autoindex is enabled in at least one context."
		result.ClientSummary = "Directory listing is enabled and should be reviewed."
		result.Evidence = joinEvidence(evidence, 3)
		return result
	}

	result.Summary = "Nginx autoindex is disabled or not configured."
	result.Evidence = "autoindex=off_or_absent"
	return result
}

type checkHiddenFilesAccess struct {
	cache *configCache
}

func (c checkHiddenFilesAccess) ID() string {
	return "nginx.hidden_files_access"
}

func (c checkHiddenFilesAccess) Title() string {
	return "Hidden files are protected"
}

func (c checkHiddenFilesAccess) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "Exposed hidden files can leak source code metadata, credentials, and server-side configuration."
	result.Recommendation = "Add a location rule that blocks dotfiles, such as location ~ /\\. { deny all; }."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Nginx appears to block access to hidden files."
	result.AdminDetails = "Looked for a hidden-file location block with deny all in nginx -T output."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "hidden files check")
	if !ok {
		return result
	}

	protected, evidence := hiddenFileProtection(config)
	if protected {
		result.Summary = "Hidden files appear to be protected by a deny rule."
		result.Evidence = evidence
		return result
	}

	result.Title = "Hidden files may be accessible"
	result.Status = checks.StatusWarn
	result.Summary = "No generic hidden-file deny rule was found."
	result.ClientSummary = "Hidden files such as .git, .env, or .ht files may be accessible."
	result.Evidence = "missing_protection=.git,.env,.ht"
	return result
}

type checkDirectoryListingRisk struct {
	cache *configCache
}

func (c checkDirectoryListingRisk) ID() string {
	return "nginx.directory_listing_risk"
}

func (c checkDirectoryListingRisk) Title() string {
	return "Public directory listing is not exposed"
}

func (c checkDirectoryListingRisk) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "Public directory listing can reveal files that were not meant to be indexed or downloaded directly."
	result.Recommendation = "Disable autoindex for public roots and serve only intentional directory indexes."
	result.Remediation = result.Recommendation
	result.ClientSummary = "No public directory listing risk was detected."
	result.AdminDetails = "Correlated autoindex on directives with common public root paths in nginx -T output."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "directory listing check")
	if !ok {
		return result
	}

	evidence := directoryListingEvidence(config)
	if len(evidence) > 0 {
		result.Title = "Public directory listing may be exposed"
		result.Status = checks.StatusWarn
		result.Summary = "A public web root and autoindex on were both detected."
		result.ClientSummary = "A public directory listing may be exposed."
		result.Evidence = joinEvidence(evidence, 4)
		return result
	}

	result.Summary = "No public root with autoindex enabled was detected."
	result.Evidence = "public_directory_listing=not_detected"
	return result
}

type checkTLSProtocols struct {
	cache *configCache
}

func (c checkTLSProtocols) ID() string {
	return "nginx.tls_protocols"
}

func (c checkTLSProtocols) Title() string {
	return "TLS protocols are modern"
}

func (c checkTLSProtocols) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "Legacy TLS protocols weaken encrypted connections and may fail compliance requirements."
	result.Recommendation = "Allow only TLSv1.2 and TLSv1.3 in ssl_protocols."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Nginx TLS protocol configuration allows modern TLS only."
	result.AdminDetails = "Checked ssl_protocols directives in nginx -T output."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "TLS protocol check")
	if !ok {
		return result
	}

	lines := sslProtocolsEvidence(config)
	if len(lines) == 0 {
		result.Title = "TLS protocols are not explicit"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "No ssl_protocols directive was found."
		result.ClientSummary = "Nginx TLS protocol configuration is not explicit."
		result.Evidence = "ssl_protocols=not_found"
		return result
	}

	result.Evidence = joinEvidence(lines, 3)
	if sslProtocolsIncludeLegacy(lines) {
		result.Title = "Legacy TLS protocols are enabled"
		result.Status = checks.StatusFail
		result.Summary = "Nginx allows TLSv1 or TLSv1.1."
		result.ClientSummary = "Legacy TLS protocols are enabled and should be disabled."
		return result
	}

	if sslProtocolsModernOnly(lines) {
		result.Summary = "Nginx ssl_protocols allows only TLSv1.2/TLSv1.3."
		return result
	}

	result.Title = "TLS protocols need review"
	result.Status = checks.StatusWarn
	result.Severity = checks.SeverityMedium
	result.Summary = "Nginx ssl_protocols contains unexpected values."
	result.ClientSummary = "Nginx TLS protocol configuration should be reviewed."
	return result
}

type checkSecurityHeaders struct {
	cache *configCache
}

func (c checkSecurityHeaders) ID() string {
	return "nginx.security_headers"
}

func (c checkSecurityHeaders) Title() string {
	return "Security headers are configured"
}

func (c checkSecurityHeaders) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "Missing browser security headers reduces protection against clickjacking, MIME sniffing, referrer leakage, and content injection."
	result.Recommendation = "Configure X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and a suitable Content-Security-Policy."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Common browser security headers are mostly configured."
	result.AdminDetails = "Checked add_header directives for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "security headers check")
	if !ok {
		return result
	}

	found := securityHeadersFound(config)
	result.Evidence = "headers=" + evidenceList(found)
	switch {
	case len(found) >= 3:
		result.Summary = "At least three common security headers are configured."
		return result
	case len(found) >= 1:
		result.Title = "Security headers are partially configured"
		result.Status = checks.StatusWarn
		result.Summary = "Only one or two common security headers were found."
		result.ClientSummary = "Browser security headers are only partially configured."
		return result
	default:
		result.Title = "Security headers are missing"
		result.Status = checks.StatusFail
		result.Summary = "No common browser security headers were found."
		result.ClientSummary = "Browser security headers are missing."
		return result
	}
}

type checkDefaultVhost struct {
	cache *configCache
}

func (c checkDefaultVhost) ID() string {
	return "nginx.default_vhost"
}

func (c checkDefaultVhost) Title() string {
	return "Default virtual host is not exposed"
}

func (c checkDefaultVhost) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Category = checks.CategoryWeb
	result.Impact = "A catch-all default virtual host can expose placeholder content or route unknown domains to the wrong site."
	result.Recommendation = "Use an intentional default vhost that returns 444/404 or remove public catch-all server blocks."
	result.Remediation = result.Recommendation
	result.ClientSummary = "No active default virtual host marker was detected."
	result.AdminDetails = "Checked nginx -T output for default_server listen directives and server_name _."

	config, ok := loadConfigForResult(ctx, c.cache, &result, "default vhost check")
	if !ok {
		return result
	}

	evidence := defaultVhostEvidence(config)
	if len(evidence) > 0 {
		result.Title = "Default virtual host is active"
		result.Status = checks.StatusWarn
		result.Summary = "A default virtual host marker was detected."
		result.ClientSummary = "A catch-all default website is active and should be reviewed."
		result.Evidence = joinEvidence(evidence, 4)
		return result
	}

	result.Summary = "No default_server or server_name _ marker was detected."
	result.Evidence = "default_vhost=not_detected"
	return result
}

func detect(ctx checks.Context) (bool, string) {
	for _, service := range ctx.Services {
		if service.Unit == "nginx.service" {
			return true, "running_service=nginx.service"
		}
	}

	paths := []string{"/usr/sbin/nginx", "/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true, "path_exists=" + path
		}
	}

	return false, "detected=false"
}

var (
	serverTokensRE      = regexp.MustCompile(`(?i)\bserver_tokens\s+(on|off)\s*;`)
	autoindexRE         = regexp.MustCompile(`(?i)\bautoindex\s+(on|off)\s*;`)
	sslProtocolsRE      = regexp.MustCompile(`(?i)\bssl_protocols\s+([^;]+);`)
	addHeaderRE         = regexp.MustCompile(`(?i)\badd_header\s+([A-Za-z0-9-]+)\b`)
	rootRE              = regexp.MustCompile(`(?i)\broot\s+([^;]+);`)
	listenDefaultRE     = regexp.MustCompile(`(?i)\blisten\s+([^;]*\bdefault_server\b[^;]*);`)
	serverNameRE        = regexp.MustCompile(`(?i)\bserver_name\s+([^;]+);`)
	denyAllRE           = regexp.MustCompile(`(?i)\bdeny\s+all\s*;`)
	modernTLSAllowed    = map[string]struct{}{"TLSv1.2": {}, "TLSv1.3": {}}
	requiredHeaders     = []string{"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"}
	publicRootFragments = []string{"/var/www", "/usr/share/nginx/html", "/srv/www", "/home/"}
)

func (c *configCache) load(ctx checks.Context) (Config, error) {
	if c == nil {
		output, err := ctx.Runner.Run(ctx.Context, "nginx", "-T")
		return ParseConfig(string(output)), err
	}
	if !c.loaded {
		output, err := ctx.Runner.Run(ctx.Context, "nginx", "-T")
		c.config = ParseConfig(string(output))
		c.err = err
		c.loaded = true
	}
	return c.config, c.err
}

func loadConfigForResult(ctx checks.Context, cache *configCache, result *checks.Result, checkName string) (Config, bool) {
	detected, detectEvidence := detect(ctx)
	if !detected {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Nginx was not detected; " + checkName + " was skipped."
		result.Evidence = detectEvidence
		result.AdminDetails = "This check requires nginx to be installed or running."
		result.HiddenInClientReport = true
		return Config{}, false
	}

	config, err := cache.load(ctx)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Could not read effective nginx configuration."
		result.ClientSummary = "Nginx configuration could not be verified."
		result.Evidence = "nginx_T=failed"
		result.Error = err.Error()
		result.AdminDetails = "Command failed: nginx -T\n" + err.Error()
		result.HiddenInClientReport = true
		return Config{}, false
	}

	return config, true
}

func serverTokensSetting(config string) string {
	return serverTokensSettingFromConfig(ParseConfig(config))
}

func serverTokensSettingFromConfig(config Config) string {
	setting := "default"
	matches := serverTokensRE.FindAllStringSubmatch(config.Clean, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		value := strings.ToLower(match[1])
		if value == "on" {
			return "on"
		}
		if value == "off" {
			setting = "off"
		}
	}

	return setting
}

func autoindexOnEvidence(config Config) []string {
	matches := autoindexRE.FindAllStringSubmatch(config.Clean, -1)
	evidence := []string{}
	for _, match := range matches {
		if len(match) != 2 || !strings.EqualFold(match[1], "on") {
			continue
		}
		evidence = append(evidence, compactWhitespace(match[0]))
	}
	return evidence
}

func hiddenFileProtection(config Config) (bool, string) {
	for _, block := range config.LocationBlocks() {
		if !containsHiddenFilePattern(block.Header) {
			continue
		}
		if !denyAllRE.MatchString(block.Body) {
			continue
		}
		return true, compactWhitespace(block.Header + " { deny all; }")
	}
	return false, "hidden_file_deny=not_found"
}

func containsHiddenFilePattern(header string) bool {
	lower := strings.ToLower(header)
	return strings.Contains(lower, `\.`) ||
		strings.Contains(lower, "/.") ||
		strings.Contains(lower, ".git") ||
		strings.Contains(lower, ".env") ||
		strings.Contains(lower, ".ht")
}

func publicRootEvidence(config Config) []string {
	matches := rootRE.FindAllStringSubmatch(config.Clean, -1)
	evidence := []string{}
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		root := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		if isPublicRoot(root) {
			evidence = append(evidence, "root="+root)
		}
	}
	return uniqueSorted(evidence)
}

func isPublicRoot(root string) bool {
	root = strings.ToLower(root)
	for _, fragment := range publicRootFragments {
		if strings.Contains(root, fragment) {
			return true
		}
	}
	return strings.Contains(root, "/public_html")
}

func directoryListingEvidence(config Config) []string {
	evidence := []string{}
	for _, block := range append(config.Blocks("server"), config.LocationBlocks()...) {
		blockConfig := ParseConfig(block.Body)
		roots := publicRootEvidence(blockConfig)
		autoindex := autoindexOnEvidence(blockConfig)
		if len(roots) == 0 || len(autoindex) == 0 {
			continue
		}
		evidence = append(evidence, roots...)
		evidence = append(evidence, autoindex...)
	}
	return uniqueSorted(evidence)
}

func sslProtocolsEvidence(config Config) []string {
	return config.DirectiveMatches(sslProtocolsRE)
}

func sslProtocolsIncludeLegacy(lines []string) bool {
	for _, line := range lines {
		for _, value := range sslProtocolValues(line) {
			if strings.EqualFold(value, "TLSv1") || strings.EqualFold(value, "TLSv1.1") {
				return true
			}
		}
	}
	return false
}

func sslProtocolsModernOnly(lines []string) bool {
	for _, line := range lines {
		values := sslProtocolValues(line)
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if _, ok := modernTLSAllowed[value]; !ok {
				return false
			}
		}
	}
	return true
}

func sslProtocolValues(line string) []string {
	match := sslProtocolsRE.FindStringSubmatch(line)
	if len(match) != 2 {
		return nil
	}

	values := []string{}
	for _, value := range strings.Fields(match[1]) {
		values = append(values, strings.Trim(value, ";"))
	}
	return values
}

func securityHeadersFound(config Config) []string {
	all := config.AddHeaders()
	required := map[string]struct{}{}
	for _, header := range requiredHeaders {
		required[header] = struct{}{}
	}

	found := []string{}
	for _, header := range all {
		if _, ok := required[header]; ok {
			found = append(found, header)
		}
	}
	sort.Strings(found)
	return found
}

func defaultVhostEvidence(config Config) []string {
	evidence := []string{}
	evidence = append(evidence, config.DirectiveMatches(listenDefaultRE)...)
	for _, match := range serverNameRE.FindAllStringSubmatch(config.Clean, -1) {
		if len(match) != 2 {
			continue
		}
		for _, value := range strings.Fields(match[1]) {
			if value == "_" {
				evidence = append(evidence, compactWhitespace(match[0]))
				break
			}
		}
	}
	return uniqueSorted(evidence)
}

func evidenceList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

func joinEvidence(values []string, limit int) string {
	values = uniqueSorted(values)
	if len(values) == 0 {
		return "none"
	}
	if len(values) > limit {
		values = values[:limit]
	}
	return strings.Join(values, "; ")
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = compactWhitespace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
