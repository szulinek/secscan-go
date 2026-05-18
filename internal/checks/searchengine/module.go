package searchengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"secscan/internal/checks"
)

const (
	moduleID = "search_engine"
	service  = "elasticsearch/opensearch"

	engineElasticsearch = "elasticsearch"
	engineOpenSearch    = "opensearch"
)

var (
	elasticsearchConfigPaths = []string{"/etc/elasticsearch/elasticsearch.yml"}
	opensearchConfigPaths    = []string{"/etc/opensearch/opensearch.yml"}
	elasticsearchSharePaths  = []string{"/usr/share/elasticsearch"}
	opensearchSharePaths     = []string{"/usr/share/opensearch"}
	elasticsearchJVMPatterns = []string{"/etc/elasticsearch/jvm.options", "/etc/elasticsearch/jvm.options.d/*"}
	opensearchJVMPatterns    = []string{"/etc/opensearch/jvm.options", "/etc/opensearch/jvm.options.d/*"}
	memInfoPath              = "/proc/meminfo"
)

type Module struct{}

type discoveryCache struct {
	loaded bool
	state  discoveryState
}

type discoveryState struct {
	detected       bool
	engine         string
	detectEvidence string
	config         Config
	configErr      error
	jvm            JVMOptions
	jvmErr         error
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
	return "Elasticsearch / OpenSearch"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &discoveryCache{}
	return []checks.Check{
		checkVersion{},
		checkClusterHealth{},
		checkBindLocalhost{cache: cache},
		checkJVMMemory{cache: cache},
		checkSecurityEnabled{cache: cache},
		checkRunsAsRoot{},
		checkBackupsSnapshots{cache: cache},
		checkTLSConfigured{cache: cache},
		checkDangerousDestructiveActions{cache: cache},
		checkFilePermissions{cache: cache},
	}
}

type checkVersion struct{}

func (c checkVersion) ID() string { return "search.version" }
func (c checkVersion) Title() string {
	return "Search engine version"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Elasticsearch or OpenSearch version was collected."
	result.ClientSummary = "Search engine version information was recorded."
	result.AdminDetails = "Executed elasticsearch --version or opensearch --version, with localhost API as a fallback."
	result.Impact = "Version inventory helps prioritize search engine patching and lifecycle decisions."
	result.Recommendation = "Keep Elasticsearch or OpenSearch on a supported and patched release."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "elasticsearch --version; opensearch --version; curl --max-time 2 -fsS http://127.0.0.1:9200"}
	result.HiddenInClientReport = true

	engine, ok := ensureDetected(ctx, &result, "version check")
	if !ok {
		return result
	}
	version, source, err := searchVersion(ctx, engine)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Search engine version could not be collected."
		result.ClientSummary = "Search engine version could not be verified."
		result.AdminDetails = "Version commands and localhost API fallback failed.\n" + err.Error()
		result.Evidence = "engine=" + engine + "; version=unknown"
		result.Error = err.Error()
		return result
	}
	result.Evidence = "engine=" + engine + "; version=" + version + "; source=" + source
	return result
}

type checkClusterHealth struct{}

func (c checkClusterHealth) ID() string { return "search.cluster_health" }
func (c checkClusterHealth) Title() string {
	return "Search cluster health is green"
}

func (c checkClusterHealth) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Search cluster health is green."
	result.ClientSummary = "Search cluster health is healthy."
	result.AdminDetails = "Queried the local _cluster/health API over loopback only."
	result.Impact = "Yellow or red cluster health can indicate missing replicas, unavailable shards, or data availability risk."
	result.Recommendation = "Investigate yellow or red cluster health and restore shard allocation to green where appropriate."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Review _cluster/health and shard allocation diagnostics before making operational changes.")
	result.Automation = checks.Automation{Shell: "curl --max-time 2 -fsS http://127.0.0.1:9200/_cluster/health"}

	if _, ok := ensureDetected(ctx, &result, "cluster health check"); !ok {
		return result
	}
	status, err := clusterHealth(ctx)
	if err != nil {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Local cluster health API was not accessible."
		result.ClientSummary = "Search cluster health could not be verified."
		result.Evidence = "status=not_accessible"
		result.HiddenInClientReport = true
		return result
	}
	result.Evidence = "status=" + status
	switch status {
	case "green":
		return result
	case "yellow":
		result.Title = "Search cluster health is yellow"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Search cluster health is yellow."
		result.ClientSummary = "Search cluster health needs attention."
	case "red":
		result.Title = "Search cluster health is red"
		result.Status = checks.StatusFail
		result.Severity = checks.SeverityHigh
		result.Summary = "Search cluster health is red."
		result.ClientSummary = "Search cluster health is high risk."
	default:
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "Search cluster health returned an unknown status."
		result.ClientSummary = "Search cluster health could not be classified."
	}
	return result
}

type checkBindLocalhost struct {
	cache *discoveryCache
}

func (c checkBindLocalhost) ID() string { return "search.bind_localhost" }
func (c checkBindLocalhost) Title() string {
	return "Search engine bind address is restricted"
}

func (c checkBindLocalhost) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Search engine listeners are restricted to localhost or private interfaces."
	result.ClientSummary = "Search engine network exposure is restricted."
	result.AdminDetails = "Checked network.host, http.host, transport.host, and ss listeners for ports 9200/9300."
	result.Impact = "A publicly exposed search API can allow data disclosure, destructive requests, or cluster compromise if authentication is weak or disabled."
	result.Recommendation = "Bind Elasticsearch or OpenSearch to localhost or private interfaces and restrict access with firewall policy."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Set network.host/http.host/transport.host to localhost or private application interfaces only.")
	result.Automation = checks.Automation{Shell: "grep -E '^\\s*(network.host|http.host|transport.host)\\s*:' /etc/elasticsearch/elasticsearch.yml /etc/opensearch/opensearch.yml 2>/dev/null; ss -tulpn | grep -E ':(9200|9300)\\b'"}

	state, ok := loadForResult(ctx, c.cache, &result, "bind address check")
	if !ok {
		return result
	}
	exposure := networkExposure(state.config, state.listens)
	result.Evidence = fmt.Sprintf("bind=%s; listen=%s", bindEvidence(state.config), listenEvidence(state.listens))
	if exposure == exposureRestricted {
		return result
	}
	result.Title = "Search engine may bind to a public interface"
	result.Status = checks.StatusWarn
	result.Summary = "Search engine bind or listener configuration includes a public or wildcard interface."
	result.ClientSummary = "Search engine may be publicly reachable."
	if exposure == exposureUnknown {
		result.Severity = checks.SeverityMedium
		result.Summary = "Search engine bind configuration could not be clearly classified."
		result.ClientSummary = "Search engine network exposure should be reviewed."
	}
	return result
}

type checkJVMMemory struct {
	cache *discoveryCache
}

func (c checkJVMMemory) ID() string { return "search.jvm_memory" }
func (c checkJVMMemory) Title() string {
	return "Search JVM heap is configured"
}

func (c checkJVMMemory) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Search JVM heap settings are configured consistently."
	result.ClientSummary = "Search engine JVM memory settings are configured."
	result.AdminDetails = "Parsed -Xms and -Xmx from jvm.options and jvm.options.d files, then compared Xmx with host RAM."
	result.Impact = "Missing or mismatched heap settings can cause unstable performance, garbage collection pressure, or host memory exhaustion."
	result.Recommendation = "Set Xms and Xmx to the same workload-appropriate value, usually no more than half of host RAM."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Configure matching -Xms and -Xmx values appropriate for host memory and workload.")
	result.Automation = checks.Automation{Shell: "grep -R '^-Xms\\|^-Xmx' /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.d /etc/opensearch/jvm.options /etc/opensearch/jvm.options.d 2>/dev/null; grep MemTotal /proc/meminfo"}

	state, ok := loadForResult(ctx, c.cache, &result, "JVM memory check")
	if !ok {
		return result
	}
	ram := readMemTotal(memInfoPath)
	result.Evidence = fmt.Sprintf("Xms=%s; Xmx=%s; RAM=%s", valueOrNotSet(state.jvm.Xms), valueOrNotSet(state.jvm.Xmx), formatBytes(ram))
	if state.jvm.Xms == "" || state.jvm.Xmx == "" {
		result.Title = "Search JVM heap settings are incomplete"
		result.Status = checks.StatusWarn
		result.Summary = "JVM -Xms or -Xmx was not found."
		result.ClientSummary = "Search engine JVM heap should be reviewed."
		return result
	}
	if !strings.EqualFold(state.jvm.Xms, state.jvm.Xmx) {
		result.Title = "Search JVM heap min and max differ"
		result.Status = checks.StatusWarn
		result.Summary = "JVM -Xms and -Xmx are not equal."
		result.ClientSummary = "Search engine JVM heap settings should match."
		return result
	}
	xmx, parsed := parseSizeBytes(state.jvm.Xmx)
	if parsed && ram > 0 && xmx > ram/2 {
		result.Title = "Search JVM heap may be too large"
		result.Status = checks.StatusWarn
		result.Summary = "JVM -Xmx is above 50% of host RAM."
		result.ClientSummary = "Search engine JVM heap may be too large."
	}
	return result
}

type checkSecurityEnabled struct {
	cache *discoveryCache
}

func (c checkSecurityEnabled) ID() string { return "search.security_enabled" }
func (c checkSecurityEnabled) Title() string {
	return "Search security is enabled"
}

func (c checkSecurityEnabled) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Search engine security/authentication is not explicitly disabled."
	result.ClientSummary = "Search engine authentication appears enabled."
	result.AdminDetails = "Checked xpack.security.enabled for Elasticsearch and plugins.security.disabled for OpenSearch."
	result.Impact = "Disabled search authentication can expose indexes, credentials, and destructive APIs to any network client that reaches the service."
	result.Recommendation = "Enable Elasticsearch xpack security or OpenSearch security plugin authentication, especially on non-local listeners."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Enable the engine security features and validate application credentials before exposing the service.")
	result.Automation = checks.Automation{Shell: "grep -E '^\\s*(xpack.security.enabled|plugins.security.disabled)\\s*:' /etc/elasticsearch/elasticsearch.yml /etc/opensearch/opensearch.yml 2>/dev/null"}

	state, ok := loadForResult(ctx, c.cache, &result, "security check")
	if !ok {
		return result
	}
	disabled, known := securityDisabled(state.engine, state.config)
	public := networkExposure(state.config, state.listens) == exposurePublic
	result.Evidence = fmt.Sprintf("engine=%s; security=%s; public_bind=%t", state.engine, securityEvidence(disabled, known), public)
	if !known {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "Search security setting was not explicitly present in configuration."
		result.ClientSummary = "Search authentication setting could not be confirmed from config."
		return result
	}
	if !disabled {
		return result
	}
	result.Title = "Search security is disabled"
	result.Status = checks.StatusWarn
	result.Summary = "Search engine security/authentication is explicitly disabled."
	result.ClientSummary = "Search engine authentication is disabled."
	if public {
		result.Severity = checks.SeverityHigh
		result.Summary = "Search engine security is disabled while the service appears publicly reachable."
	}
	return result
}

type checkRunsAsRoot struct{}

func (c checkRunsAsRoot) ID() string { return "search.runs_as_root" }
func (c checkRunsAsRoot) Title() string {
	return "Search engine does not run as root"
}

func (c checkRunsAsRoot) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "Search engine service does not run as root."
	result.ClientSummary = "Search engine process user looks restricted."
	result.AdminDetails = "Checked systemd User= and process owner for Elasticsearch or OpenSearch."
	result.Impact = "Running the search engine as root increases the impact of process compromise and plugin vulnerabilities."
	result.Recommendation = "Run Elasticsearch or OpenSearch as a dedicated unprivileged service user."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Configure the service to run as the dedicated elasticsearch or opensearch user.")
	result.Automation = checks.Automation{Shell: "systemctl show elasticsearch.service opensearch.service -p User --value; ps -o user= -C elasticsearch -C opensearch"}

	engine, ok := ensureDetected(ctx, &result, "process user check")
	if !ok {
		return result
	}
	userName, source, err := processUser(ctx, engine)
	if err != nil {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "Search engine process user could not be verified."
		result.ClientSummary = "Search engine process user could not be verified."
		result.Evidence = "user=unknown; source=unavailable"
		result.HiddenInClientReport = true
		return result
	}
	result.Evidence = "user=" + userName + "; source=" + source
	if userName == "root" {
		result.Title = "Search engine runs as root"
		result.Status = checks.StatusFail
		result.Summary = "Search engine service or process appears to run as root."
		result.ClientSummary = "Search engine is running with excessive privileges."
	}
	return result
}

type checkBackupsSnapshots struct {
	cache *discoveryCache
}

func (c checkBackupsSnapshots) ID() string { return "search.backups_snapshots" }
func (c checkBackupsSnapshots) Title() string {
	return "Search snapshots are configured"
}

func (c checkBackupsSnapshots) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Search snapshot repository configuration was detected."
	result.ClientSummary = "Search engine snapshot backup traces were detected."
	result.AdminDetails = "Checked path.repo in configuration and queried the local _snapshot API when available."
	result.Impact = "Without snapshots, accidental deletion, corruption, or ransomware can cause permanent index data loss."
	result.Recommendation = "Configure and monitor snapshot repositories with tested restore procedures."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Configure a snapshot repository and schedule backups with restore testing.")
	result.Automation = checks.Automation{Shell: "grep -E '^\\s*path.repo\\s*:' /etc/elasticsearch/elasticsearch.yml /etc/opensearch/opensearch.yml 2>/dev/null; curl --max-time 2 -fsS http://127.0.0.1:9200/_snapshot"}

	state, ok := loadForResult(ctx, c.cache, &result, "snapshot backup check")
	if !ok {
		return result
	}
	repos := state.config.ListValue("path.repo")
	repoCount, _ := snapshotRepoCount(ctx)
	result.Evidence = fmt.Sprintf("path.repo=%s; repo_count=%s", limitedJoin(repos, 5), countEvidence(repoCount))
	if len(repos) > 0 || repoCount > 0 {
		return result
	}
	result.Title = "Search snapshots were not detected"
	result.Status = checks.StatusWarn
	result.Summary = "No path.repo setting or snapshot repositories were detected."
	result.ClientSummary = "Search engine snapshots should be configured."
	return result
}

type checkTLSConfigured struct {
	cache *discoveryCache
}

func (c checkTLSConfigured) ID() string { return "search.tls_configured" }
func (c checkTLSConfigured) Title() string {
	return "Search HTTP TLS is configured where needed"
}

func (c checkTLSConfigured) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Search HTTP TLS settings were checked."
	result.ClientSummary = "Search engine transport encryption was checked."
	result.AdminDetails = "Checked HTTP TLS settings for Elasticsearch and OpenSearch."
	result.Impact = "Unencrypted public search traffic can expose credentials, index data, and query contents."
	result.Recommendation = "Enable HTTP TLS for any non-local Elasticsearch or OpenSearch listener."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Enable HTTP TLS and deploy trusted certificates for non-local search API access.")
	result.Automation = checks.Automation{Shell: "grep -E '^\\s*(xpack.security.http.ssl.enabled|plugins.security.ssl.http.enabled)\\s*:' /etc/elasticsearch/elasticsearch.yml /etc/opensearch/opensearch.yml 2>/dev/null"}

	state, ok := loadForResult(ctx, c.cache, &result, "TLS check")
	if !ok {
		return result
	}
	tlsEnabled, tlsKnown := tlsConfigured(state.engine, state.config)
	public := networkExposure(state.config, state.listens) == exposurePublic
	result.Evidence = fmt.Sprintf("tls=%s; public_bind=%t", boolEvidence(tlsEnabled, tlsKnown), public)
	if tlsEnabled {
		result.Status = checks.StatusPass
		result.Severity = checks.SeverityLow
		result.Summary = "Search HTTP TLS is enabled."
		result.ClientSummary = "Search engine HTTP TLS is configured."
		return result
	}
	if public {
		result.Title = "Search HTTP TLS is not enabled on a public listener"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Search engine appears publicly reachable and HTTP TLS is not enabled."
		result.ClientSummary = "Search engine transport encryption should be enabled."
		return result
	}
	result.Summary = "Search HTTP TLS is not clearly enabled, but the listener appears local/private."
	result.ClientSummary = "Search engine HTTP TLS is not clearly enabled for local/private access."
	return result
}

type checkDangerousDestructiveActions struct {
	cache *discoveryCache
}

func (c checkDangerousDestructiveActions) ID() string { return "search.dangerous_destructive_actions" }
func (c checkDangerousDestructiveActions) Title() string {
	return "Search destructive actions require explicit names"
}

func (c checkDangerousDestructiveActions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Destructive wildcard actions are blocked by configuration."
	result.ClientSummary = "Search destructive action safety is configured."
	result.AdminDetails = "Checked action.destructive_requires_name in search engine configuration."
	result.Impact = "Allowing wildcard destructive actions increases the risk of accidental or malicious index deletion."
	result.Recommendation = "Set action.destructive_requires_name to true."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Set action.destructive_requires_name: true in the active configuration.")
	result.Automation = checks.Automation{Shell: "grep -E '^\\s*action.destructive_requires_name\\s*:' /etc/elasticsearch/elasticsearch.yml /etc/opensearch/opensearch.yml 2>/dev/null"}

	state, ok := loadForResult(ctx, c.cache, &result, "destructive action check")
	if !ok {
		return result
	}
	value := state.config.StringValue("action.destructive_requires_name")
	result.Evidence = "value=" + valueOrNotSet(value)
	if isTrue(value) {
		return result
	}
	result.Title = "Search destructive action guard is not enabled"
	result.Status = checks.StatusWarn
	if value == "" {
		result.Summary = "action.destructive_requires_name was not found in configuration."
		result.ClientSummary = "Search destructive action guard is not explicit."
		return result
	}
	result.Summary = "action.destructive_requires_name is false."
	result.ClientSummary = "Search destructive action guard should be enabled."
	return result
}

type checkFilePermissions struct {
	cache *discoveryCache
}

func (c checkFilePermissions) ID() string { return "search.file_permissions" }
func (c checkFilePermissions) Title() string {
	return "Search config files are not writable by broad principals"
}

func (c checkFilePermissions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Search configuration file permissions are not group- or world-writable."
	result.ClientSummary = "Search engine configuration file permissions look restricted."
	result.AdminDetails = "Checked elasticsearch.yml/opensearch.yml and JVM options files for group- and world-writable modes."
	result.Impact = "Writable search configuration files can allow unsafe network exposure, disabled authentication, or arbitrary JVM changes."
	result.Recommendation = "Keep search engine configuration owned by root or the service administrator and not writable by group or world."
	result.Remediation = result.Recommendation
	result.RemediationSteps = searchSteps("Remove world-writable permissions and review whether group write access is required.")
	result.Automation = checks.Automation{Shell: "find /etc/elasticsearch /etc/opensearch -maxdepth 3 -type f \\( -name '*.yml' -o -name 'jvm.options' -o -name '*.options' \\) -exec ls -l {} + 2>/dev/null"}

	state, ok := loadForResult(ctx, c.cache, &result, "file permission check")
	if !ok {
		return result
	}
	files := append([]string{}, state.config.Files...)
	files = append(files, state.jvm.Files...)
	files = uniqueStrings(files)
	if len(files) == 0 {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Search configuration files were not found."
		result.ClientSummary = "Search configuration permissions could not be verified."
		result.Evidence = "config_files=not_found"
		result.HiddenInClientReport = true
		return result
	}
	issues := []string{}
	world := false
	group := false
	for _, path := range files {
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
	result.Evidence = "config_files_checked=" + strconv.Itoa(len(files))
	if len(issues) > 0 {
		result.Evidence = limitedJoin(issues, 10)
	}
	if world {
		result.Title = "Search config file is world-writable"
		result.Status = checks.StatusFail
		result.Severity = checks.SeverityHigh
		result.Summary = "At least one search configuration file is world-writable."
		result.ClientSummary = "Search configuration permissions are unsafe."
		return result
	}
	if group {
		result.Title = "Search config file is group-writable"
		result.Status = checks.StatusWarn
		result.Summary = "At least one search configuration file is group-writable."
		result.ClientSummary = "Search configuration permissions should be reviewed."
	}
	return result
}

func newResult(id, title string, severity checks.Severity, status checks.Status) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, severity, status)
	result.Category = checks.CategoryDatabase
	return result
}

type engineDetection struct {
	Engine   string
	Evidence string
}

func detect(ctx checks.Context) (bool, string) {
	detection, ok := detectEngine(ctx)
	return ok, detection.Evidence
}

func detectEngine(ctx checks.Context) (engineDetection, bool) {
	if !linuxTarget(ctx) {
		return engineDetection{Evidence: "detected=false goos=" + ctx.Host.GOOS}, false
	}
	for _, svc := range ctx.Services {
		unit := strings.ToLower(svc.Unit)
		if unit == "elasticsearch.service" {
			return engineDetection{Engine: engineElasticsearch, Evidence: "engine=elasticsearch; running_service=" + svc.Unit}, true
		}
		if unit == "opensearch.service" {
			return engineDetection{Engine: engineOpenSearch, Evidence: "engine=opensearch; running_service=" + svc.Unit}, true
		}
	}
	if ctx.Runner != nil {
		if output, err := ctx.Runner.Run(ctx.Context, "pgrep", "-x", "elasticsearch"); err == nil && strings.TrimSpace(string(output)) != "" {
			return engineDetection{Engine: engineElasticsearch, Evidence: "engine=elasticsearch; process=elasticsearch"}, true
		}
		if output, err := ctx.Runner.Run(ctx.Context, "pgrep", "-x", "opensearch"); err == nil && strings.TrimSpace(string(output)) != "" {
			return engineDetection{Engine: engineOpenSearch, Evidence: "engine=opensearch; process=opensearch"}, true
		}
	}
	if path, ok := firstExistingPath(elasticsearchConfigPaths); ok {
		return engineDetection{Engine: engineElasticsearch, Evidence: "engine=elasticsearch; path_exists=" + path}, true
	}
	if path, ok := firstExistingPath(opensearchConfigPaths); ok {
		return engineDetection{Engine: engineOpenSearch, Evidence: "engine=opensearch; path_exists=" + path}, true
	}
	if path, ok := firstExistingPath(elasticsearchSharePaths); ok {
		return engineDetection{Engine: engineElasticsearch, Evidence: "engine=elasticsearch; path_exists=" + path}, true
	}
	if path, ok := firstExistingPath(opensearchSharePaths); ok {
		return engineDetection{Engine: engineOpenSearch, Evidence: "engine=opensearch; path_exists=" + path}, true
	}
	return engineDetection{Evidence: "detected=false"}, false
}

func linuxTarget(ctx checks.Context) bool {
	if ctx.Host.GOOS == "" {
		return true
	}
	return ctx.Host.GOOS == "linux" || len(ctx.Host.OSRelease) > 0
}

func ensureDetected(ctx checks.Context, result *checks.Result, checkName string) (string, bool) {
	detection, detected := detectEngine(ctx)
	if detected {
		return detection.Engine, true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Elasticsearch or OpenSearch was not detected; " + checkName + " was skipped."
	result.ClientSummary = "Search engine was not detected."
	result.AdminDetails = "This check requires Elasticsearch or OpenSearch to be installed or running."
	result.Evidence = detection.Evidence
	result.HiddenInClientReport = true
	return "", false
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
	detection, detected := detectEngine(ctx)
	state := discoveryState{
		detected:       detected,
		engine:         detection.Engine,
		detectEvidence: detection.Evidence,
	}
	if !detected {
		return state
	}
	state.config, state.configErr = loadConfigFromPaths(configPathsForEngine(state.engine))
	state.jvm, state.jvmErr = loadJVMOptionsFromPatterns(jvmPatternsForEngine(state.engine))
	state.listens, state.ssErr = collectListens(ctx)
	return state
}

func loadForResult(ctx checks.Context, cache *discoveryCache, result *checks.Result, checkName string) (discoveryState, bool) {
	state, ok := cache.load(ctx)
	if ok {
		if len(state.config.Files) > 0 {
			result.AdminDetails += "\nConfig files: " + limitedJoin(state.config.Files, 5)
		}
		if len(state.jvm.Files) > 0 {
			result.AdminDetails += "\nJVM files: " + limitedJoin(state.jvm.Files, 5)
		}
		return state, true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Elasticsearch or OpenSearch was not detected; " + checkName + " was skipped."
	result.ClientSummary = "Search engine was not detected."
	result.AdminDetails = "This check requires Elasticsearch or OpenSearch to be installed or running."
	result.Evidence = state.detectEvidence
	result.HiddenInClientReport = true
	return discoveryState{}, false
}

func configPathsForEngine(engine string) []string {
	if engine == engineOpenSearch {
		return opensearchConfigPaths
	}
	return elasticsearchConfigPaths
}

func jvmPatternsForEngine(engine string) []string {
	if engine == engineOpenSearch {
		return opensearchJVMPatterns
	}
	return elasticsearchJVMPatterns
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func searchVersion(ctx checks.Context, engine string) (string, string, error) {
	if ctx.Runner == nil {
		return "", "", fmt.Errorf("runner is not available")
	}
	command := "elasticsearch"
	if engine == engineOpenSearch {
		command = "opensearch"
	}
	errs := []string{}
	if output, err := ctx.Runner.Run(ctx.Context, command, "--version"); err == nil {
		if version := parseVersion(string(output)); version != "" {
			return version, command, nil
		}
		errs = append(errs, command+": version not found")
	} else {
		errs = append(errs, command+": "+err.Error())
	}
	if version, err := versionFromAPI(ctx); err == nil && version != "" {
		return version, "localhost_api", nil
	} else if err != nil {
		errs = append(errs, "localhost_api: "+err.Error())
	}
	return "", "", errors.New(strings.Join(errs, "; "))
}

var versionRE = regexp.MustCompile(`\b[0-9]+(?:\.[0-9]+){1,3}(?:[-+~][A-Za-z0-9._:-]+)?\b`)

func parseVersion(output string) string {
	return strings.TrimSpace(versionRE.FindString(output))
}

func versionFromAPI(ctx checks.Context) (string, error) {
	body, err := curlLocal(ctx, "")
	if err != nil {
		return "", err
	}
	var payload struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", err
	}
	if payload.Version.Number == "" {
		return "", fmt.Errorf("version.number not found")
	}
	return payload.Version.Number, nil
}

func clusterHealth(ctx checks.Context) (string, error) {
	body, err := curlLocal(ctx, "/_cluster/health")
	if err != nil {
		return "", err
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", err
	}
	status := strings.ToLower(strings.TrimSpace(payload.Status))
	if status == "" {
		return "", fmt.Errorf("cluster health status not found")
	}
	return status, nil
}

func snapshotRepoCount(ctx checks.Context) (int, error) {
	body, err := curlLocal(ctx, "/_snapshot")
	if err != nil {
		return 0, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func curlLocal(ctx checks.Context, path string) (string, error) {
	if ctx.Runner == nil {
		return "", fmt.Errorf("runner is not available")
	}
	httpURL := "http://127.0.0.1:9200" + path
	if output, err := ctx.Runner.Run(ctx.Context, "curl", "--max-time", "2", "-fsS", httpURL); err == nil {
		return string(output), nil
	}
	httpsURL := "https://127.0.0.1:9200" + path
	output, err := ctx.Runner.Run(ctx.Context, "curl", "--max-time", "2", "-k", "-fsS", httpsURL)
	return string(output), err
}

type listenEndpoint struct {
	Address string
	Port    string
	Process string
}

func collectListens(ctx checks.Context) ([]listenEndpoint, error) {
	if ctx.Runner == nil {
		return nil, fmt.Errorf("runner is not available")
	}
	output, err := ctx.Runner.Run(ctx.Context, "ss", "-tulpn")
	if err != nil {
		return nil, err
	}
	return parseSS(string(output)), nil
}

func parseSS(output string) []listenEndpoint {
	endpoints := []listenEndpoint{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" || !(strings.Contains(lower, "elasticsearch") || strings.Contains(lower, "opensearch") || strings.Contains(line, ":9200") || strings.Contains(line, ":9300")) {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields {
			address, port, ok := splitHostPortLoose(field)
			if ok && (port == "9200" || port == "9300") {
				endpoints = append(endpoints, listenEndpoint{Address: address, Port: port, Process: processName(line)})
				break
			}
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Port != endpoints[j].Port {
			return endpoints[i].Port < endpoints[j].Port
		}
		return endpoints[i].Address < endpoints[j].Address
	})
	return endpoints
}

type exposure int

const (
	exposureUnknown exposure = iota
	exposureRestricted
	exposurePublic
)

func networkExposure(config Config, listens []listenEndpoint) exposure {
	values := bindValues(config)
	if len(values) > 0 {
		for _, value := range values {
			if isPublicAddress(value) {
				return exposurePublic
			}
			if !isRestrictedAddress(value) {
				return exposureUnknown
			}
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
		if !isRestrictedAddress(listen.Address) {
			return exposureUnknown
		}
	}
	return exposureRestricted
}

func bindValues(config Config) []string {
	values := []string{}
	for _, key := range []string{"network.host", "http.host", "transport.host"} {
		if value := config.StringValue(key); value != "" {
			values = append(values, parseListValue(value)...)
		}
	}
	return values
}

func bindEvidence(config Config) string {
	values := bindValues(config)
	if len(values) == 0 {
		return "not_set"
	}
	return strings.Join(values, ",")
}

func listenEvidence(listens []listenEndpoint) string {
	if len(listens) == 0 {
		return "none"
	}
	values := []string{}
	for _, listen := range listens {
		values = append(values, listen.Address+":"+listen.Port+"/"+listen.Process)
		if len(values) >= 5 {
			break
		}
	}
	return strings.Join(values, ",")
}

func securityDisabled(engine string, config Config) (bool, bool) {
	if engine == engineOpenSearch {
		value, ok := config.BoolValue("plugins.security.disabled")
		return value, ok
	}
	value, ok := config.BoolValue("xpack.security.enabled")
	if !ok {
		return false, false
	}
	return !value, true
}

func tlsConfigured(engine string, config Config) (bool, bool) {
	if engine == engineOpenSearch {
		return config.BoolValue("plugins.security.ssl.http.enabled")
	}
	return config.BoolValue("xpack.security.http.ssl.enabled")
}

func processUser(ctx checks.Context, engine string) (string, string, error) {
	if ctx.Runner == nil {
		return "", "", fmt.Errorf("runner is not available")
	}
	unit := "elasticsearch.service"
	process := "elasticsearch"
	if engine == engineOpenSearch {
		unit = "opensearch.service"
		process = "opensearch"
	}
	if output, err := ctx.Runner.Run(ctx.Context, "systemctl", "show", unit, "-p", "User", "--value"); err == nil {
		value := strings.TrimSpace(string(output))
		if value == "" {
			value = "root"
		}
		return value, "systemd", nil
	}
	output, err := ctx.Runner.Run(ctx.Context, "ps", "-o", "user=", "-C", process)
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return "", "", fmt.Errorf("process user not found")
	}
	return fields[0], "process", nil
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

func splitHostPortLoose(value string) (string, string, bool) {
	value = strings.Trim(strings.TrimSpace(value), `"'(),;`)
	if value == "" {
		return "", "", false
	}
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end > 0 {
			host := value[1:end]
			port := value[end+2:]
			if isPort(port) {
				return normalizeHost(host), port, true
			}
		}
	}
	if host, port, err := net.SplitHostPort(value); err == nil && isPort(port) {
		return normalizeHost(host), port, true
	}
	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return "", "", false
	}
	host := value[:idx]
	port := strings.TrimRight(value[idx+1:], ",;")
	if !isPort(port) {
		return "", "", false
	}
	return normalizeHost(host), port, true
}

func normalizeHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "*" {
		return "0.0.0.0"
	}
	return host
}

func isPort(port string) bool {
	if port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func processName(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "opensearch"):
		return "opensearch"
	case strings.Contains(lower, "elasticsearch"):
		return "elasticsearch"
	default:
		return "search"
	}
}

func isPublicAddress(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if lower == "*" || lower == "0.0.0.0" || lower == "::" || lower == "::0" || lower == "::/0" || lower == "_global_" {
		return true
	}
	if strings.Contains(lower, "_site_") {
		return false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate())
}

func isRestrictedAddress(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if lower == "localhost" || strings.Contains(lower, "_local_") || strings.Contains(lower, "_site_") {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func isTrue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "yes" || value == "on" || value == "1" || value == "enabled"
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

func boolEvidence(value, known bool) string {
	if !known {
		return "unknown"
	}
	if value {
		return "true"
	}
	return "false"
}

func securityEvidence(disabled, known bool) string {
	if !known {
		return "unknown"
	}
	if disabled {
		return "disabled"
	}
	return "enabled"
}

func countEvidence(count int) string {
	if count < 0 {
		return "unknown"
	}
	return strconv.Itoa(count)
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

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func searchSteps(action string) []string {
	return []string{
		"Review the active Elasticsearch or OpenSearch configuration.",
		action,
		"Validate the change and apply it during an approved search maintenance window.",
	}
}
