package linux

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"secscan/internal/checks"
	"secscan/internal/system"
)

const (
	moduleID = "linux"
	service  = "linux"
)

type Module struct{}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "Linux baseline"
}

func (m Module) Detect(ctx checks.Context) bool {
	return ctx.Host.GOOS == "linux" || len(ctx.Host.OSRelease) > 0
}

func (m Module) Checks() []checks.Check {
	return []checks.Check{
		checkOSVersion{},
		checkKernelVersion{},
		checkSecurityUpdatesAvailable{},
		checkUnattendedUpgrades{},
		checkFirewallStatus{},
		checkProtectionDaemon{},
	}
}

type checkOSVersion struct{}

func (c checkOSVersion) ID() string {
	return "linux.os_version"
}

func (c checkOSVersion) Title() string {
	return "Operating system version"
}

func (c checkOSVersion) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategorySystem
	result.Summary = "Operating system metadata was collected from os-release."
	result.ClientSummary = "Operating system version was recorded for the audit."
	result.AdminDetails = "Read PRETTY_NAME, VERSION_ID, and VERSION_CODENAME from detected os-release data."
	result.Impact = "Accurate OS inventory helps prioritize patching and lifecycle decisions."
	result.Recommendation = "Keep the operating system on a supported release and patch regularly."
	result.Remediation = result.Recommendation
	result.Evidence = osVersionEvidence(ctx.Host)
	result.HiddenInClientReport = true
	return result
}

type checkKernelVersion struct{}

func (c checkKernelVersion) ID() string {
	return "linux.kernel_version"
}

func (c checkKernelVersion) Title() string {
	return "Kernel version"
}

func (c checkKernelVersion) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategorySystem
	result.Impact = "Kernel version inventory helps identify missing security updates and unsupported kernels."
	result.Recommendation = "Keep the kernel updated through the distribution package manager."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Kernel version was recorded for the audit."
	result.AdminDetails = "Collected kernel release with uname -r."
	result.HiddenInClientReport = true

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Kernel version check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "uname", "-r")
	if err != nil {
		result.Status = checks.StatusError
		result.Summary = "Kernel version could not be collected."
		result.ClientSummary = "Kernel version could not be verified."
		result.Evidence = "uname -r failed"
		result.AdminDetails = "Command failed: uname -r\n" + err.Error()
		result.Error = err.Error()
		return result
	}

	kernel := strings.TrimSpace(string(output))
	if kernel == "" {
		kernel = "unknown"
	}
	result.Summary = "Kernel version was collected."
	result.Evidence = "kernel=" + kernel
	return result
}

type checkSecurityUpdatesAvailable struct{}

func (c checkSecurityUpdatesAvailable) ID() string {
	return "linux.security_updates_available"
}

func (c checkSecurityUpdatesAvailable) Title() string {
	return "Security updates are installed"
}

func (c checkSecurityUpdatesAvailable) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySystem
	result.Impact = "Uninstalled security updates leave known vulnerabilities exposed."
	result.Recommendation = "Apply available security updates during the next safe maintenance window."
	result.Remediation = result.Recommendation
	result.ClientSummary = "No pending security updates were detected."
	result.AdminDetails = "Simulated package upgrade with apt-get -s and counted security repository upgrades."

	if !isDebianLike(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Security update check applies to Debian-like systems only."
		result.Evidence = "os_release=" + osReleaseID(ctx.Host)
		result.AdminDetails = "This check currently targets Debian/Ubuntu apt based systems."
		result.HiddenInClientReport = true
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
	if err != nil {
		result.Status = checks.StatusError
		result.Summary = "Security updates could not be checked safely."
		result.ClientSummary = "Pending security updates could not be verified."
		result.Evidence = "apt_get_simulation=failed"
		result.AdminDetails = "Command failed: apt-get -s -o Debug::NoLocking=true upgrade\n" + err.Error()
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	count := countSecurityUpdates(string(output))
	result.Evidence = "security_updates=" + strconv.Itoa(count)
	if count > 0 {
		result.Title = "Security updates are available"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d security update(s) appear to be available.", count)
		result.ClientSummary = "Security updates are available and should be installed."
		return result
	}

	result.Title = "No security updates are available"
	result.Summary = "No pending security updates were detected."
	return result
}

type checkUnattendedUpgrades struct{}

func (c checkUnattendedUpgrades) ID() string {
	return "linux.unattended_upgrades"
}

func (c checkUnattendedUpgrades) Title() string {
	return "Unattended security upgrades are installed and enabled"
}

func (c checkUnattendedUpgrades) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusFail)
	result.Category = checks.CategorySystem
	result.Impact = "Missing automatic security updates increases exposure to known vulnerabilities between maintenance windows."
	result.Recommendation = "Install and enable unattended-upgrades or document an equivalent patch-management process."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Automatic security updates are not confirmed on this server."

	if !isDebianLike(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Unattended-upgrades check applies to Debian-like systems only."
		result.Evidence = "os_release=" + osReleaseID(ctx.Host)
		result.AdminDetails = "This check currently targets Debian/Ubuntu style unattended-upgrades."
		result.HiddenInClientReport = true
		return result
	}

	installed, installEvidence := unattendedInstalled(ctx)
	enabled, enabledEvidence := unattendedEnabled(ctx)
	result.Evidence = strings.Join(compact([]string{installEvidence, enabledEvidence}), "; ")
	result.AdminDetails = "Expected package unattended-upgrades to be installed and either apt periodic unattended upgrades or a related systemd timer/service to be enabled."

	if installed && enabled {
		result.Status = checks.StatusPass
		result.Summary = "Unattended security upgrades appear to be installed and enabled."
		result.ClientSummary = "Automatic security updates are enabled."
		return result
	}

	result.Summary = "Unattended security upgrades are not fully enabled."
	return result
}

type checkFirewallStatus struct{}

func (c checkFirewallStatus) ID() string {
	return "linux.firewall_status"
}

func (c checkFirewallStatus) Title() string {
	return "Host firewall is present"
}

func (c checkFirewallStatus) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, "firewall", c.Title(), checks.SeverityMedium, checks.StatusWarn)
	result.Category = checks.CategoryFirewall
	result.Impact = "Without a detected host firewall, exposed services may be reachable more broadly than intended."
	result.Recommendation = "Enable and verify a firewall layer such as CSF/LFD, nftables, iptables, or UFW."
	result.Remediation = result.Recommendation
	result.ClientSummary = "A host-level firewall was not confirmed."

	if ctx.Host.GOOS != "linux" && len(ctx.Host.OSRelease) == 0 {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Firewall check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.AdminDetails = "The current host is not detected as Linux."
		result.HiddenInClientReport = true
		return result
	}

	status := detectFirewallStatus(ctx)
	result.AdminDetails = "Detection looked for CSF/LFD, nftables, iptables, and UFW using running services, known config paths, and read-only command probes."

	if len(status.ActiveSignals) > 0 {
		result.Status = checks.StatusPass
		result.Summary = "An active host firewall signal was detected."
		result.ClientSummary = "A host-level firewall appears to be active."
		result.Evidence = strings.Join(status.ActiveSignals, "; ")
		return result
	}

	if len(status.Errors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "Firewall status could not be verified."
		result.ClientSummary = "Host firewall status could not be verified."
		result.Evidence = strings.Join(status.Errors, "; ")
		result.AdminDetails = "Firewall command probes failed. " + strings.Join(status.Errors, "; ")
		result.Error = strings.Join(status.Errors, "; ")
		result.HiddenInClientReport = true
		return result
	}

	evidence := "firewall=not_detected"
	if len(status.InstalledSignals) > 0 {
		evidence += "; " + strings.Join(status.InstalledSignals, "; ")
	}
	result.Evidence = evidence
	result.Summary = "No active host firewall signal was detected."
	return result
}

type checkProtectionDaemon struct{}

func (c checkProtectionDaemon) ID() string {
	return "linux.protection_daemon"
}

func (c checkProtectionDaemon) Title() string {
	return "Brute-force protection daemon is running"
}

func (c checkProtectionDaemon) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusWarn)
	result.Category = checks.CategorySystem
	result.Impact = "Without fail2ban or CrowdSec, repeated authentication attacks may not be throttled automatically."
	result.Recommendation = "Enable fail2ban or CrowdSec for exposed SSH, mail, FTP, and web authentication endpoints."
	result.Remediation = result.Recommendation
	result.ClientSummary = "No brute-force protection daemon was confirmed."
	result.AdminDetails = "Checked running systemd units for fail2ban.service and crowdsec.service."

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Protection daemon check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.HiddenInClientReport = true
		return result
	}

	detected := protectionDaemonServices(ctx)
	if len(detected) > 0 {
		result.Status = checks.StatusPass
		result.Summary = "A brute-force protection daemon is running."
		result.ClientSummary = "Brute-force protection appears to be active."
		result.Evidence = strings.Join(detected, "; ")
		return result
	}

	result.Summary = "No fail2ban or CrowdSec service was detected as running."
	result.Evidence = "protection_daemon=not_detected"
	return result
}

func unattendedInstalled(ctx checks.Context) (bool, string) {
	output, err := ctx.Runner.Run(ctx.Context, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
	value := strings.TrimSpace(string(output))
	if err != nil {
		return false, "dpkg-query unattended-upgrades: not installed"
	}

	if strings.Contains(value, "install ok installed") {
		return true, "package=unattended-upgrades installed"
	}

	return false, "package=unattended-upgrades status=" + value
}

func unattendedEnabled(ctx checks.Context) (bool, string) {
	if aptPeriodicEnabled() {
		return true, "apt periodic unattended-upgrade enabled"
	}

	units := []string{"unattended-upgrades.service", "apt-daily-upgrade.timer", "apt-daily.timer"}
	for _, unit := range units {
		output, err := ctx.Runner.Run(ctx.Context, "systemctl", "is-enabled", unit)
		value := strings.TrimSpace(string(output))
		if err == nil && (value == "enabled" || value == "static" || value == "generated") {
			return true, unit + "=" + value
		}
	}

	return false, "unattended-upgrades systemd/apt periodic enablement not confirmed"
}

func osVersionEvidence(info system.Info) string {
	values := []string{
		"PRETTY_NAME=" + valueOrUnknown(info.OSRelease["PRETTY_NAME"]),
		"VERSION_ID=" + valueOrUnknown(info.OSRelease["VERSION_ID"]),
		"VERSION_CODENAME=" + valueOrUnknown(info.OSRelease["VERSION_CODENAME"]),
	}
	return strings.Join(values, "; ")
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func countSecurityUpdates(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "inst ") {
			continue
		}
		if strings.Contains(lower, "security") || strings.Contains(lower, "-security") {
			count++
		}
	}
	return count
}

func aptPeriodicEnabled() bool {
	paths := []string{
		"/etc/apt/apt.conf.d/20auto-upgrades",
		"/etc/apt/apt.conf.d/50unattended-upgrades",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, `APT::Periodic::Unattended-Upgrade "1"`) || strings.Contains(content, `APT::Periodic::Unattended-Upgrade "1";`) {
			return true
		}
	}

	return false
}

type firewallStatus struct {
	ActiveSignals    []string
	InstalledSignals []string
	Errors           []string
}

func detectFirewallStatus(ctx checks.Context) firewallStatus {
	status := firewallStatus{}
	serviceNames := []string{"csf.service", "lfd.service", "nftables.service", "ufw.service", "firewalld.service"}
	for _, service := range ctx.Services {
		for _, expected := range serviceNames {
			if service.Unit == expected {
				status.ActiveSignals = append(status.ActiveSignals, "running_service="+service.Unit)
			}
		}
	}

	paths := []string{"/etc/csf/csf.conf", "/usr/sbin/csf", "/usr/sbin/lfd", "/etc/ufw/ufw.conf"}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			status.InstalledSignals = append(status.InstalledSignals, "path_exists="+path)
		}
	}

	if output, err := ctx.Runner.Run(ctx.Context, "ufw", "status"); err == nil {
		if strings.Contains(strings.ToLower(string(output)), "status: active") {
			status.ActiveSignals = append(status.ActiveSignals, "ufw=status active")
		}
	} else if !isMissingCommandError(err) {
		status.Errors = append(status.Errors, "ufw=probe_error")
	}
	if output, err := ctx.Runner.Run(ctx.Context, "nft", "list", "ruleset"); err == nil {
		if strings.TrimSpace(string(output)) != "" {
			status.ActiveSignals = append(status.ActiveSignals, "nft=ruleset present")
		}
	} else if !isMissingCommandError(err) {
		status.Errors = append(status.Errors, "nft=probe_error")
	}
	if output, err := ctx.Runner.Run(ctx.Context, "iptables", "-S"); err == nil {
		if iptablesLooksConfigured(string(output)) {
			status.ActiveSignals = append(status.ActiveSignals, "iptables=rules present")
		}
	} else if !isMissingCommandError(err) {
		status.Errors = append(status.Errors, "iptables=probe_error")
	}

	status.ActiveSignals = unique(status.ActiveSignals)
	status.InstalledSignals = unique(status.InstalledSignals)
	status.Errors = unique(status.Errors)
	sort.Strings(status.ActiveSignals)
	sort.Strings(status.InstalledSignals)
	sort.Strings(status.Errors)
	return status
}

func iptablesLooksConfigured(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A ") || strings.Contains(line, " DROP") || strings.Contains(line, " REJECT") {
			return true
		}
	}

	return false
}

func isDebianLike(info system.Info) bool {
	id := strings.ToLower(info.OSRelease["ID"])
	like := strings.ToLower(info.OSRelease["ID_LIKE"])
	return id == "debian" || id == "ubuntu" || strings.Contains(like, "debian") || strings.Contains(like, "ubuntu")
}

func isLinuxHost(info system.Info) bool {
	return info.GOOS == "linux" || len(info.OSRelease) > 0
}

func isMissingCommandError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "executable file not found") ||
		strings.Contains(value, "command not found") ||
		strings.Contains(value, "no such file or directory")
}

func protectionDaemonServices(ctx checks.Context) []string {
	detected := []string{}
	for _, service := range ctx.Services {
		switch service.Unit {
		case "fail2ban.service", "crowdsec.service":
			detected = append(detected, "running_service="+service.Unit)
		}
	}
	return unique(detected)
}

func osReleaseID(info system.Info) string {
	if id := info.OSRelease["ID"]; id != "" {
		return id
	}
	return "unknown"
}

func compact(values []string) []string {
	out := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
