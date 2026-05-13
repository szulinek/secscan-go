package varnish

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "varnish"
	service  = "varnish"
)

var (
	varnishDefaultVCLPath    = "/etc/varnish/default.vcl"
	varnishDefaultConfigPath = "/etc/default/varnish"
	varnishParamsPath        = "/etc/varnish/varnish.params"
	varnishdBinaryPaths      = []string{"/usr/sbin/varnishd", "/usr/local/sbin/varnishd", "/usr/bin/varnishd", "/usr/local/bin/varnishd"}
	varnishstatBinaryPaths   = []string{"/usr/bin/varnishstat", "/usr/local/bin/varnishstat"}
	lookPath                 = exec.LookPath
)

type Module struct{}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "Varnish"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	return []checks.Check{
		checkVersion{},
		checkStorageMalloc{},
		checkCacheHitRatio{},
		checkLRUNukedObjects{},
		checkBackendHealth{},
		checkListenPorts{},
	}
}

type checkVersion struct{}

func (c checkVersion) ID() string {
	return "varnish.version"
}

func (c checkVersion) Title() string {
	return "Varnish version"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Varnish version was collected."
	result.ClientSummary = "Varnish version information was recorded."
	result.AdminDetails = "Executed varnishd -V and parsed the version string."
	result.Impact = "Version inventory helps prioritize patching and lifecycle decisions for Varnish."
	result.Recommendation = "Keep Varnish on a supported and patched release."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "varnishd -V"}
	result.HiddenInClientReport = true

	if !ensureVarnishDetected(ctx, &result, "Varnish version check") {
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "varnishd", "-V")
	if err != nil {
		return commandError(result, "varnishd -V", err)
	}
	version := parseVersion(string(output))
	if version == "" {
		version = "unknown"
	}
	result.Evidence = "version=" + version
	return result
}

type checkStorageMalloc struct{}

func (c checkStorageMalloc) ID() string {
	return "varnish.storage_malloc"
}

func (c checkStorageMalloc) Title() string {
	return "Varnish storage uses malloc"
}

func (c checkStorageMalloc) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Varnish storage is configured to use malloc."
	result.ClientSummary = "Varnish uses memory-backed cache storage."
	result.AdminDetails = "Checked systemd ExecStart, /etc/default/varnish, and /etc/varnish/varnish.params for -s storage arguments."
	result.Impact = "File-backed or unclear storage can reduce cache performance and make capacity behavior harder to predict."
	result.Recommendation = "Use explicit malloc storage sized for the host and workload unless file storage is intentionally required."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review the active Varnish startup options.",
		"Set an explicit -s malloc,<size> storage backend sized for available memory.",
		"Validate the planned change and apply it during an approved maintenance window.",
	}
	result.Automation = checks.Automation{Shell: "systemctl show varnish.service -p ExecStart --value; grep -R -- '-s ' /etc/default/varnish /etc/varnish/varnish.params 2>/dev/null"}

	if !ensureVarnishDetected(ctx, &result, "Varnish storage check") {
		return result
	}

	storage := storageConfigs(ctx)
	result.Evidence = storageEvidence(storage)
	if storage.Kind == "malloc" {
		return result
	}

	result.Title = "Varnish storage is not clearly malloc"
	result.Status = checks.StatusWarn
	if storage.Kind == "file" {
		result.Summary = "Varnish appears to use file-backed storage."
		result.ClientSummary = "Varnish cache storage is file-backed and should be reviewed."
		return result
	}
	result.Summary = "Varnish storage configuration could not be clearly identified."
	result.ClientSummary = "Varnish cache storage configuration should be reviewed."
	return result
}

type checkCacheHitRatio struct{}

func (c checkCacheHitRatio) ID() string {
	return "varnish.cache_hit_ratio"
}

func (c checkCacheHitRatio) Title() string {
	return "Varnish cache hit ratio"
}

func (c checkCacheHitRatio) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusInfo)
	result.Summary = "Varnish cache hit ratio was checked."
	result.ClientSummary = "Varnish cache effectiveness was checked."
	result.AdminDetails = "Executed varnishstat -1 and calculated MAIN.cache_hit / (MAIN.cache_hit + MAIN.cache_miss)."
	result.Impact = "A low cache hit ratio can increase backend load and reduce site performance."
	result.Recommendation = "Review VCL, cache headers, backend behavior, and cache size when hit ratio is persistently low."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review varnishstat cache hit and miss counters over representative traffic.",
		"Check VCL and origin cache headers for unnecessary pass or uncacheable responses.",
		"Tune cache policy and storage size based on traffic and object churn.",
	}
	result.Automation = checks.Automation{Shell: "varnishstat -1"}

	sample, ok := statForResult(ctx, &result, "cache hit ratio check")
	if !ok {
		return result
	}

	hit, hitOK := sample.Value("MAIN.cache_hit")
	miss, missOK := sample.Value("MAIN.cache_miss")
	if !hitOK || !missOK || hit+miss <= 0 {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "Varnish cache hit ratio did not have enough data."
		result.ClientSummary = "Varnish cache hit ratio has insufficient data."
		result.Evidence = fmt.Sprintf("hit=%s; miss=%s; ratio=not_available", statValue(hit, hitOK), statValue(miss, missOK))
		return result
	}

	ratio := hit / (hit + miss)
	result.Status = checks.StatusPass
	result.Severity = checks.SeverityLow
	result.Summary = "Varnish cache hit ratio is at or above 70%."
	result.ClientSummary = "Varnish cache hit ratio looks healthy."
	result.Evidence = fmt.Sprintf("hit=%.0f; miss=%.0f; ratio=%.2f", hit, miss, ratio)
	if ratio < 0.70 {
		result.Title = "Varnish cache hit ratio is low"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Varnish cache hit ratio is below 70%."
		result.ClientSummary = "Varnish cache hit ratio is low."
	}
	return result
}

type checkLRUNukedObjects struct{}

func (c checkLRUNukedObjects) ID() string {
	return "varnish.lru_nuked_objects"
}

func (c checkLRUNukedObjects) Title() string {
	return "Varnish LRU nuked objects"
}

func (c checkLRUNukedObjects) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Varnish is not evicting objects due to cache pressure."
	result.ClientSummary = "Varnish cache eviction pressure was not detected."
	result.AdminDetails = "Read MAIN.n_lru_nuked or MAIN.lru_nuked_objects from varnishstat -1."
	result.Impact = "LRU nuked objects indicate cache storage pressure, which can reduce hit ratio and increase backend load."
	result.Recommendation = "Increase malloc storage, improve cache policy, or reduce object churn if LRU nuking persists."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review varnishstat LRU nuked counters over time.",
		"Compare cache size, object churn, and hit ratio.",
		"Increase storage or tune caching rules during an approved maintenance window if pressure persists.",
	}
	result.Automation = checks.Automation{Shell: "varnishstat -1"}

	sample, ok := statForResult(ctx, &result, "LRU nuked objects check")
	if !ok {
		return result
	}

	value, valueOK := sample.Value("MAIN.n_lru_nuked", "MAIN.lru_nuked_objects")
	if !valueOK {
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityInfo
		result.Summary = "Varnish LRU nuked counter was not present in varnishstat output."
		result.ClientSummary = "Varnish LRU nuked counter was not available."
		result.Evidence = "lru_nuked=not_available"
		return result
	}

	result.Evidence = fmt.Sprintf("lru_nuked=%.0f", value)
	if value > 0 {
		result.Title = "Varnish is evicting objects under LRU pressure"
		result.Status = checks.StatusWarn
		result.Summary = "Varnish reports LRU nuked objects."
		result.ClientSummary = "Varnish cache storage pressure was detected."
	}
	if value > 1000 {
		result.Severity = checks.SeverityHigh
	}
	return result
}

type checkBackendHealth struct{}

func (c checkBackendHealth) ID() string {
	return "varnish.backend_health"
}

func (c checkBackendHealth) Title() string {
	return "Varnish backend health"
}

func (c checkBackendHealth) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Varnish backend health metrics were checked."
	result.ClientSummary = "Varnish backend health was checked."
	result.AdminDetails = "Looked for backend health counters in varnishstat -1, such as VBE.*.happy."
	result.Impact = "Unhealthy backends can cause cache misses, errors, and degraded application availability."
	result.Recommendation = "Review backend health probes and origin availability when unhealthy backends are reported."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review varnishstat backend health counters.",
		"Check Varnish health probes and backend origin availability.",
		"Fix unhealthy backend services or probe configuration.",
	}
	result.Automation = checks.Automation{Shell: "varnishstat -1"}

	sample, ok := statForResult(ctx, &result, "backend health check")
	if !ok {
		return result
	}

	healthy, unhealthy, found := sample.BackendHealth()
	if !found {
		return notApplicable(result, "backend_health=not_available", "Varnish backend health metrics were not present.")
	}

	result.Evidence = fmt.Sprintf("backend_healthy=%d; backend_unhealthy=%d", healthy, unhealthy)
	if unhealthy > 0 {
		result.Title = "Varnish has unhealthy backends"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Varnish reports one or more unhealthy backends."
		result.ClientSummary = "One or more Varnish backends are unhealthy."
		return result
	}
	return result
}

type checkListenPorts struct{}

func (c checkListenPorts) ID() string {
	return "varnish.listen_ports"
}

func (c checkListenPorts) Title() string {
	return "Varnish listening ports"
}

func (c checkListenPorts) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Varnish listening ports were inventoried."
	result.ClientSummary = "Varnish listening ports were recorded."
	result.AdminDetails = "Executed ss -tulpn and looked for varnishd listening sockets."
	result.Impact = "A publicly exposed Varnish admin interface can allow unauthorized cache administration."
	result.Recommendation = "Keep the Varnish admin interface bound to localhost or a private management network."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review ss -tulpn output for Varnish admin listener exposure.",
		"Bind the admin interface to localhost or a private management interface.",
		"Restrict network access with firewall policy.",
	}
	result.Automation = checks.Automation{Shell: "ss -tulpn"}

	if !ensureVarnishDetected(ctx, &result, "listen ports check") {
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "ss", "-tulpn")
	if err != nil {
		return commandError(result, "ss -tulpn", err)
	}

	listeners := parseListeners(string(output))
	if len(listeners) == 0 {
		result.Evidence = "listen_ports=not_detected"
		return result
	}

	result.Evidence = listenersEvidence(listeners, 10)
	for _, listener := range listeners {
		if listener.Port == "6082" && !isLoopbackHost(listener.Host) {
			result.Title = "Varnish admin interface is publicly exposed"
			result.Status = checks.StatusWarn
			result.Severity = checks.SeverityHigh
			result.Summary = "Varnish admin interface appears to listen on a non-loopback address."
			result.ClientSummary = "Varnish admin interface may be publicly reachable."
			result.Evidence = listener.Evidence()
			return result
		}
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
		if strings.EqualFold(svc.Unit, "varnish.service") {
			return true, "running_service=" + svc.Unit
		}
	}
	if path, ok := firstExistingPath(varnishdBinaryPaths); ok {
		return true, "binary=" + path
	}
	if path, ok := firstExistingPath(varnishstatBinaryPaths); ok {
		return true, "binary=" + path
	}
	if lookPath != nil {
		if path, err := lookPath("varnishd"); err == nil && path != "" {
			return true, "binary=" + path
		}
		if path, err := lookPath("varnishstat"); err == nil && path != "" {
			return true, "binary=" + path
		}
	}
	for _, path := range []string{varnishDefaultVCLPath, varnishDefaultConfigPath, varnishParamsPath} {
		if _, err := os.Stat(path); err == nil {
			return true, "path_exists=" + path
		}
	}
	return false, "detected=false"
}

func ensureVarnishDetected(ctx checks.Context, result *checks.Result, checkName string) bool {
	detected, evidence := detect(ctx)
	if detected {
		return true
	}
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Varnish was not detected; " + checkName + " was skipped."
	result.ClientSummary = "Varnish was not detected."
	result.AdminDetails = "This check requires Varnish to be installed or running."
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return false
}

func commandError(result checks.Result, command string, err error) checks.Result {
	result.Status = checks.StatusError
	result.Severity = checks.SeverityMedium
	result.Summary = "Varnish diagnostic command could not be executed."
	result.ClientSummary = "Varnish security checks could not query the service."
	result.AdminDetails = "Command failed: " + command + "\n" + err.Error()
	result.Evidence = "command=failed " + command
	result.Error = err.Error()
	result.HiddenInClientReport = true
	return result
}

func statForResult(ctx checks.Context, result *checks.Result, checkName string) (StatSample, bool) {
	if !ensureVarnishDetected(ctx, result, checkName) {
		return StatSample{}, false
	}
	output, err := ctx.Runner.Run(ctx.Context, "varnishstat", "-1")
	if err != nil {
		*result = commandError(*result, "varnishstat -1", err)
		return StatSample{}, false
	}
	return ParseStat(string(output)), true
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

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func parseVersion(output string) string {
	re := regexp.MustCompile(`(?i)varnish[- ]([0-9]+(?:\.[0-9]+){1,3})`)
	matches := re.FindStringSubmatch(output)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

type StorageConfig struct {
	Kind   string
	Size   string
	Source string
}

func storageConfigs(ctx checks.Context) StorageConfig {
	candidates := []StorageConfig{}
	if output, err := ctx.Runner.Run(ctx.Context, "systemctl", "show", "varnish.service", "-p", "ExecStart", "--value"); err == nil {
		candidates = append(candidates, parseStorage(string(output), "systemd")...)
	}
	for _, item := range []struct {
		path   string
		source string
	}{
		{path: varnishDefaultConfigPath, source: "default"},
		{path: varnishParamsPath, source: "params"},
	} {
		data, err := os.ReadFile(item.path)
		if err != nil {
			continue
		}
		candidates = append(candidates, parseStorage(string(data), item.source)...)
	}

	for _, candidate := range candidates {
		if candidate.Kind == "malloc" {
			return candidate
		}
	}
	for _, candidate := range candidates {
		if candidate.Kind == "file" {
			return candidate
		}
	}
	return StorageConfig{Kind: "unknown", Size: "unknown", Source: "not_found"}
}

func parseStorage(content, source string) []StorageConfig {
	storage := []StorageConfig{}
	re := regexp.MustCompile(`(?:^|[\s"'])\-s\s*([A-Za-z0-9_./:-]+(?:,[^\s"']+)*)`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		if len(match) != 2 {
			continue
		}
		spec := strings.Trim(match[1], `"',`)
		parts := strings.Split(spec, ",")
		if len(parts) == 0 {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(parts[0]))
		size := "unknown"
		if len(parts) > 1 {
			size = strings.TrimSpace(parts[len(parts)-1])
		}
		storage = append(storage, StorageConfig{Kind: kind, Size: size, Source: source})
	}
	return storage
}

func storageEvidence(storage StorageConfig) string {
	return fmt.Sprintf("storage=%s,size=%s,source=%s", storage.Kind, storage.Size, storage.Source)
}

func statValue(value float64, ok bool) string {
	if !ok {
		return "not_available"
	}
	return strconv.FormatFloat(value, 'f', 0, 64)
}

type Listener struct {
	Host    string
	Port    string
	Process string
}

func (l Listener) Evidence() string {
	return fmt.Sprintf("%s:%s process=%s", l.Host, l.Port, l.Process)
}

func parseListeners(output string) []Listener {
	listeners := []Listener{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(strings.ToLower(line), "varnish") {
			continue
		}
		host, port, ok := listenAddress(line)
		if !ok {
			continue
		}
		listeners = append(listeners, Listener{Host: host, Port: port, Process: processName(line)})
	}
	sort.SliceStable(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].Host < listeners[j].Host
	})
	return listeners
}

func listenAddress(line string) (string, string, bool) {
	fields := strings.Fields(line)
	for _, field := range fields {
		host, port, ok := splitHostPortLoose(field)
		if ok {
			return host, port, true
		}
	}
	return "", "", false
}

func processName(line string) string {
	if strings.Contains(strings.ToLower(line), "varnishd") {
		return "varnishd"
	}
	return "varnish"
}

func listenersEvidence(listeners []Listener, limit int) string {
	values := []string{}
	for _, listener := range listeners {
		values = append(values, listener.Evidence())
		if limit > 0 && len(values) >= limit {
			break
		}
	}
	return strings.Join(values, "; ")
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

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
