package linux

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"secscan/internal/checks"
	"secscan/internal/system"
)

const (
	moduleID = "linux"
	service  = "linux"
)

type configPermissionTarget struct {
	Key      string
	Path     string
	MaxMode  fs.FileMode
	Critical bool
}

var configPermissionTargets = []configPermissionTarget{
	{Key: "passwd", Path: "/etc/passwd", MaxMode: 0644},
	{Key: "shadow", Path: "/etc/shadow", MaxMode: 0640, Critical: true},
	{Key: "sudoers", Path: "/etc/sudoers", MaxMode: 0440, Critical: true},
	{Key: "sshd_config", Path: "/etc/ssh/sshd_config", MaxMode: 0644},
}

var (
	sudoersPath       = "/etc/sudoers"
	sudoersDropInPath = "/etc/sudoers.d"
	passwdPath        = "/etc/passwd"
	authLogPaths      = []string{"/var/log/auth.log", "/var/log/auth.log.1"}
	limitsConfPath    = "/etc/security/limits.conf"
	limitsDropInPath  = "/etc/security/limits.d"
	nowFunc           = time.Now
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
		checkListeningPorts{},
		checkConfigPermissions{},
		checkSudoersRiskyEntries{},
		checkUnknownUsers{},
		checkAppArmorStatus{},
		checkAuthLogRecentLogins{},
		checkForkbombLimits{},
		checkProcessSnapshot{},
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

type checkListeningPorts struct{}

func (c checkListeningPorts) ID() string {
	return "linux.listening_ports"
}

func (c checkListeningPorts) Title() string {
	return "Public listening ports"
}

func (c checkListeningPorts) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategoryFirewall
	result.Impact = "Unexpected public listening ports increase the externally reachable attack surface."
	result.Recommendation = "Close unnecessary public listeners or document and firewall them explicitly."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Public listening ports were collected for inventory."
	result.AdminDetails = "Collected listening TCP/UDP sockets with ss -tulpn and filtered wildcard bind addresses."
	result.HiddenInClientReport = true

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Listening port check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "ss", "-tulpn")
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Listening ports could not be collected."
		result.ClientSummary = "Public listening ports could not be verified."
		result.Evidence = "ss_tulpn=failed"
		result.AdminDetails = "Command failed: ss -tulpn\n" + err.Error()
		result.Error = err.Error()
		return result
	}

	ports := parseSSListeningPorts(string(output))
	if len(ports) == 0 {
		result.Summary = "No wildcard listening ports were detected."
		result.Evidence = "public_listeners=none"
		return result
	}

	unexpected := unexpectedListeningPorts(ports)
	if len(unexpected) > 0 {
		result.Title = "Unexpected public listening ports detected"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = fmt.Sprintf("%d public listening port(s) are outside the allowlist.", len(unexpected))
		result.ClientSummary = "Unexpected public listening ports are exposed."
		result.Evidence = listeningPortsEvidence(unexpected)
		result.HiddenInClientReport = false
		return result
	}

	result.Summary = "Wildcard listening ports are limited to allowed services."
	result.Evidence = listeningPortsEvidence(ports)
	return result
}

type checkConfigPermissions struct{}

func (c checkConfigPermissions) ID() string {
	return "linux.config_permissions"
}

func (c checkConfigPermissions) Title() string {
	return "Sensitive config permissions are safe"
}

func (c checkConfigPermissions) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySystem
	result.Impact = "Overly broad permissions on sensitive config files can expose credentials or allow unsafe configuration changes."
	result.Recommendation = "Restrict sensitive files to distribution-safe ownership and mode defaults."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Sensitive system config file permissions appear safe."
	result.AdminDetails = "Checked /etc/passwd, /etc/shadow, /etc/sudoers, and /etc/ssh/sshd_config mode bits."

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Config permission check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.HiddenInClientReport = true
		return result
	}

	status := inspectConfigPermissions(configPermissionTargets)
	result.Evidence = strings.Join(status.Evidence, "; ")
	if len(status.Errors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "Config file permissions could not be checked."
		result.ClientSummary = "Sensitive config file permissions could not be verified."
		result.Evidence = strings.Join(status.Errors, "; ")
		result.AdminDetails = "Failed to stat one or more sensitive config files. " + result.Evidence
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return result
	}

	if len(status.Issues) > 0 {
		result.Title = "Sensitive config permissions are too broad"
		result.Status = checks.StatusWarn
		if status.HasCritical {
			result.Status = checks.StatusFail
			result.Severity = checks.SeverityHigh
		}
		result.Summary = "One or more sensitive config files have broader permissions than expected."
		result.ClientSummary = "Sensitive system config permissions need administrator review."
		result.Evidence = strings.Join(status.Issues, "; ")
		return result
	}

	result.Summary = "Sensitive config file permissions are within expected limits."
	return result
}

type checkSudoersRiskyEntries struct{}

func (c checkSudoersRiskyEntries) ID() string {
	return "linux.sudoers_risky_entries"
}

func (c checkSudoersRiskyEntries) Title() string {
	return "No risky sudoers entries detected"
}

func (c checkSudoersRiskyEntries) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySystem
	result.Impact = "Risky sudoers entries can allow broad privilege escalation or passwordless administrative actions."
	result.Recommendation = "Limit sudo rules to specific users, commands, and operational needs; avoid broad NOPASSWD rules."
	result.Remediation = result.Recommendation
	result.ClientSummary = "No risky sudoers rules were detected."
	result.AdminDetails = "Parsed /etc/sudoers and regular files in /etc/sudoers.d for NOPASSWD and ALL=(ALL) ALL entries."

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Sudoers check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.HiddenInClientReport = true
		return result
	}

	findings, readErrors := riskySudoersEntries()
	if len(readErrors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "Sudoers files could not be checked."
		result.ClientSummary = "Sudoers rules could not be verified."
		result.Evidence = strings.Join(readErrors, "; ")
		result.AdminDetails = "Failed to read one or more sudoers files. " + result.Evidence
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return result
	}

	if len(findings) > 0 {
		result.Title = "Risky sudoers entries detected"
		result.Status = checks.StatusWarn
		result.Summary = "Risky sudoers entries were found."
		result.ClientSummary = "Some sudo rules may allow overly broad administrative access."
		result.Evidence = strings.Join(findings, "; ")
		return result
	}

	result.Summary = "No risky sudoers entries were found."
	result.Evidence = "sudoers_risks=none"
	return result
}

type checkUnknownUsers struct{}

func (c checkUnknownUsers) ID() string {
	return "linux.unknown_users"
}

func (c checkUnknownUsers) Title() string {
	return "Interactive users reviewed"
}

func (c checkUnknownUsers) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategorySystem
	result.Impact = "Unexpected interactive users can indicate unmanaged access or stale accounts."
	result.Recommendation = "Review interactive users and remove or document accounts that are no longer needed."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Interactive system users were reviewed."
	result.AdminDetails = "Parsed passwd entries with UID >= 1000 and shells other than nologin or false."
	result.HiddenInClientReport = true

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Interactive user check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		return result
	}

	users, err := interactivePasswdUsers(passwdPath)
	if err != nil {
		result.Status = checks.StatusError
		result.Summary = "Interactive users could not be checked."
		result.ClientSummary = "Interactive system users could not be verified."
		result.Evidence = "passwd=read_error"
		result.AdminDetails = "Failed to parse " + passwdPath + ". " + err.Error()
		result.Error = err.Error()
		return result
	}

	unknown := unknownInteractiveUsers(users)
	result.Evidence = passwdUsersEvidence(users)
	if len(unknown) > 0 {
		result.Title = "Unknown interactive users detected"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Interactive users outside the allowlist were detected."
		result.ClientSummary = "Some interactive system users need administrator review."
		result.Evidence = passwdUsersEvidence(unknown)
		result.HiddenInClientReport = false
		return result
	}

	result.Summary = "No interactive users outside the allowlist were detected."
	return result
}

type checkAppArmorStatus struct{}

func (c checkAppArmorStatus) ID() string {
	return "linux.apparmor_status"
}

func (c checkAppArmorStatus) Title() string {
	return "AppArmor is active"
}

func (c checkAppArmorStatus) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySystem
	result.Impact = "Mandatory access controls reduce the impact of compromised services."
	result.Recommendation = "Enable AppArmor and keep service profiles loaded where supported."
	result.Remediation = result.Recommendation
	result.ClientSummary = "AppArmor appears to be active."
	result.AdminDetails = "Checked aa-status first, then systemctl status apparmor."

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "AppArmor check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.HiddenInClientReport = true
		return result
	}

	status := detectAppArmorStatus(ctx)
	result.Evidence = status.Evidence
	switch status.State {
	case "active":
		result.Summary = "AppArmor appears to be active."
		return result
	case "missing":
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "AppArmor was not detected on this system."
		result.ClientSummary = "AppArmor is not installed or not available on this system."
		result.HiddenInClientReport = true
		return result
	default:
		result.Title = "AppArmor is not active"
		result.Status = checks.StatusWarn
		result.Summary = "AppArmor is installed but not confirmed as active."
		result.ClientSummary = "AppArmor is not confirmed as active."
		return result
	}
}

type checkAuthLogRecentLogins struct{}

func (c checkAuthLogRecentLogins) ID() string {
	return "linux.auth_log_recent_logins"
}

func (c checkAuthLogRecentLogins) Title() string {
	return "Recent SSH login activity"
}

func (c checkAuthLogRecentLogins) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategorySSH
	result.Impact = "A high number of failed SSH logins can indicate password guessing or exposure to automated attacks."
	result.Recommendation = "Review SSH exposure, enforce key-based access, and keep brute-force protection enabled."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Recent SSH login activity was reviewed."
	result.AdminDetails = "Parsed auth.log and auth.log.1 for accepted and failed SSH logins from the last 60 days."
	result.HiddenInClientReport = true

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Auth log check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		return result
	}

	counts, err := recentSSHLoginCounts(authLogPaths, nowFunc())
	if err != nil {
		result.Status = checks.StatusError
		result.Summary = "Recent SSH login activity could not be checked."
		result.ClientSummary = "Recent SSH login activity could not be verified."
		result.Evidence = "auth_log=read_error"
		result.AdminDetails = "Failed to read auth log files. " + err.Error()
		result.Error = err.Error()
		return result
	}
	if !counts.FoundLog {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Auth log files were not found."
		result.Evidence = "auth_log=not_found"
		return result
	}

	result.Evidence = fmt.Sprintf("accepted_count=%d; failed_count=%d", counts.Accepted, counts.Failed)
	if counts.Failed > 100 {
		result.Title = "High number of failed SSH logins"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "A high number of failed SSH logins was detected in recent auth logs."
		result.ClientSummary = "SSH is seeing many failed login attempts."
		result.HiddenInClientReport = false
		return result
	}

	result.Summary = "Recent SSH login activity is within the expected range."
	return result
}

type checkForkbombLimits struct{}

func (c checkForkbombLimits) ID() string {
	return "linux.forkbomb_limits"
}

func (c checkForkbombLimits) Title() string {
	return "Process limits are configured"
}

func (c checkForkbombLimits) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySystem
	result.Impact = "Missing nproc limits can make process exhaustion easier during abuse or application failure."
	result.Recommendation = "Define sane nproc limits in limits.conf or limits.d for interactive and service users."
	result.Remediation = result.Recommendation
	result.ClientSummary = "Process count limits appear to be configured."
	result.AdminDetails = "Checked /etc/security/limits.conf and regular files in /etc/security/limits.d for nproc entries."

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Process limit check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		result.HiddenInClientReport = true
		return result
	}

	entries, readErrors := nprocLimitEntries()
	if len(readErrors) > 0 {
		result.Status = checks.StatusError
		result.Summary = "Process limit files could not be checked."
		result.ClientSummary = "Process count limits could not be verified."
		result.Evidence = strings.Join(readErrors, "; ")
		result.AdminDetails = "Failed to read one or more limits files. " + result.Evidence
		result.Error = result.Evidence
		result.HiddenInClientReport = true
		return result
	}

	if len(entries) == 0 {
		result.Title = "Process limits are not configured"
		result.Status = checks.StatusWarn
		result.Summary = "No nproc limits were found in limits configuration."
		result.ClientSummary = "Process count limits are not confirmed."
		result.Evidence = "nproc_limits=not_found"
		return result
	}

	result.Summary = "nproc limits were found in limits configuration."
	result.Evidence = strings.Join(entries, "; ")
	return result
}

type checkProcessSnapshot struct{}

func (c checkProcessSnapshot) ID() string {
	return "linux.process_snapshot"
}

func (c checkProcessSnapshot) Title() string {
	return "Process snapshot reviewed"
}

func (c checkProcessSnapshot) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityInfo, checks.StatusInfo)
	result.Category = checks.CategorySystem
	result.Impact = "Suspicious root-owned processes can indicate compromise or unsafe temporary execution."
	result.Recommendation = "Review unusual root-owned processes and verify their executable path and owner."
	result.Remediation = result.Recommendation
	result.ClientSummary = "A process snapshot was collected for administrator review."
	result.AdminDetails = "Collected ps aux output, summarized top CPU/MEM processes, and flagged root processes from temporary paths or deleted binaries."
	result.HiddenInClientReport = true

	if !isLinuxHost(ctx.Host) {
		result.Status = checks.StatusNotApplicable
		result.Summary = "Process snapshot check applies to Linux systems only."
		result.Evidence = "goos=" + ctx.Host.GOOS
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "ps", "aux")
	if err != nil {
		result.Status = checks.StatusError
		result.Summary = "Process snapshot could not be collected."
		result.ClientSummary = "Running processes could not be verified."
		result.Evidence = "ps_aux=failed"
		result.AdminDetails = "Command failed: ps aux\n" + err.Error()
		result.Error = err.Error()
		return result
	}

	processes := parsePSAux(string(output))
	if len(processes) == 0 {
		result.Summary = "No processes were parsed from ps output."
		result.Evidence = "processes=none"
		return result
	}

	suspicious := suspiciousRootProcesses(processes)
	if len(suspicious) > 0 {
		result.Title = "Suspicious root-owned process detected"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "A root-owned process with an unusual executable path was detected."
		result.ClientSummary = "One root-owned process needs administrator review."
		result.Evidence = "suspicious=" + processEvidence(suspicious, 3) + "; top=" + processEvidence(topProcesses(processes, 3), 3)
		result.HiddenInClientReport = false
		return result
	}

	result.Summary = "No suspicious root-owned processes were detected."
	result.Evidence = "top=" + processEvidence(topProcesses(processes, 5), 5)
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

type listeningPort struct {
	Proto   string
	Address string
	Port    string
	Process string
}

func parseSSListeningPorts(output string) []listeningPort {
	ports := []listeningPort{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || strings.EqualFold(fields[0], "netid") {
			continue
		}

		proto := strings.ToLower(fields[0])
		local := fields[4]
		address, port, ok := splitAddressPort(local)
		if !ok || !isWildcardAddress(address) {
			continue
		}

		process := "-"
		if len(fields) > 6 {
			process = processName(strings.Join(fields[6:], " "))
		}
		ports = append(ports, listeningPort{
			Proto:   proto,
			Address: address,
			Port:    port,
			Process: process,
		})
	}

	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Port == ports[j].Port {
			return ports[i].Proto < ports[j].Proto
		}
		return ports[i].Port < ports[j].Port
	})
	return ports
}

func splitAddressPort(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end < 0 {
			return "", "", false
		}
		return value[1:end], value[end+2:], true
	}

	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func isWildcardAddress(address string) bool {
	address = strings.Trim(address, "[]")
	return address == "0.0.0.0" || address == "::" || address == "*" || address == "::ffff:0.0.0.0"
}

func processName(value string) string {
	start := strings.Index(value, `"`)
	if start < 0 {
		return valueOrUnknown(strings.TrimSpace(value))
	}
	end := strings.Index(value[start+1:], `"`)
	if end < 0 {
		return valueOrUnknown(strings.TrimSpace(value))
	}
	return value[start+1 : start+1+end]
}

func unexpectedListeningPorts(ports []listeningPort) []listeningPort {
	unexpected := []listeningPort{}
	for _, port := range ports {
		if _, ok := allowedPublicPorts[port.Port]; !ok {
			unexpected = append(unexpected, port)
		}
	}
	return unexpected
}

var allowedPublicPorts = map[string]struct{}{
	"22":    {},
	"25":    {},
	"53":    {},
	"80":    {},
	"110":   {},
	"143":   {},
	"443":   {},
	"465":   {},
	"587":   {},
	"993":   {},
	"995":   {},
	"2222":  {},
	"40022": {},
}

func listeningPortsEvidence(ports []listeningPort) string {
	values := []string{}
	for _, port := range ports {
		values = append(values, strings.Join([]string{port.Proto, port.Address, port.Port, port.Process}, "/"))
	}
	return strings.Join(values, "; ")
}

type configPermissionStatus struct {
	Evidence    []string
	Issues      []string
	Errors      []string
	HasCritical bool
}

func inspectConfigPermissions(targets []configPermissionTarget) configPermissionStatus {
	status := configPermissionStatus{}
	for _, target := range targets {
		info, err := os.Stat(target.Path)
		if err != nil {
			status.Errors = append(status.Errors, target.Key+"=stat_error")
			continue
		}

		mode := info.Mode().Perm()
		status.Evidence = append(status.Evidence, target.Key+"="+modeString(mode))
		if mode&^target.MaxMode == 0 {
			continue
		}

		status.Issues = append(status.Issues, target.Key+"="+modeString(mode)+">"+modeString(target.MaxMode))
		if target.Critical || mode&0002 != 0 {
			status.HasCritical = true
		}
	}

	return status
}

func modeString(mode fs.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

func riskySudoersEntries() ([]string, []string) {
	files, err := sudoersFiles()
	if err != nil {
		return nil, []string{"sudoers=glob_error"}
	}

	findings := []string{}
	readErrors := []string{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			readErrors = append(readErrors, sudoersEvidenceName(path)+"=read_error")
			continue
		}

		findings = append(findings, riskySudoersLines(path, string(data))...)
	}

	return unique(findings), unique(readErrors)
}

func sudoersFiles() ([]string, error) {
	files := []string{}
	if _, err := os.Stat(sudoersPath); err == nil {
		files = append(files, sudoersPath)
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		files = append(files, sudoersPath)
	}

	matches, err := filepath.Glob(filepath.Join(sudoersDropInPath, "*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, path)
	}

	return files, nil
}

func riskySudoersLines(path, content string) []string {
	findings := []string{}
	for _, line := range strings.Split(content, "\n") {
		line = stripSudoersComment(line)
		if line == "" {
			continue
		}

		upper := strings.ToUpper(line)
		name := sudoersEvidenceName(path)
		if strings.Contains(upper, "NOPASSWD") {
			findings = append(findings, name+":NOPASSWD")
		}
		if strings.Contains(strings.Join(strings.Fields(upper), ""), "ALL=(ALL)ALL") {
			findings = append(findings, name+":ALL=(ALL)ALL")
		}
	}
	return findings
}

func stripSudoersComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.HasPrefix(line, "#") {
		return ""
	}
	if index := strings.Index(line, "#"); index >= 0 {
		line = line[:index]
	}
	return strings.TrimSpace(line)
}

func sudoersEvidenceName(path string) string {
	base := filepath.Base(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "sudoers"
	}
	return base
}

type passwdUser struct {
	Name  string
	UID   int
	Shell string
}

var knownInteractiveUsers = map[string]struct{}{
	"root":   {},
	"lh":     {},
	"admin":  {},
	"deploy": {},
}

func interactivePasswdUsers(path string) ([]passwdUser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	users := []passwdUser{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 1000 {
			continue
		}
		shell := strings.TrimSpace(fields[6])
		if isDisabledShell(shell) {
			continue
		}

		users = append(users, passwdUser{
			Name:  fields[0],
			UID:   uid,
			Shell: shell,
		})
	}

	sort.SliceStable(users, func(i, j int) bool {
		if users[i].UID == users[j].UID {
			return users[i].Name < users[j].Name
		}
		return users[i].UID < users[j].UID
	})
	return users, nil
}

func isDisabledShell(shell string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(shell)))
	return base == "nologin" || base == "false"
}

func unknownInteractiveUsers(users []passwdUser) []passwdUser {
	unknown := []passwdUser{}
	for _, user := range users {
		if _, ok := knownInteractiveUsers[user.Name]; ok {
			continue
		}
		unknown = append(unknown, user)
	}
	return unknown
}

func passwdUsersEvidence(users []passwdUser) string {
	if len(users) == 0 {
		return "interactive_users=none"
	}

	values := []string{}
	for _, user := range users {
		values = append(values, fmt.Sprintf("%s:%d:%s", user.Name, user.UID, user.Shell))
	}
	return strings.Join(values, "; ")
}

type appArmorStatus struct {
	State    string
	Evidence string
}

func detectAppArmorStatus(ctx checks.Context) appArmorStatus {
	output, err := ctx.Runner.Run(ctx.Context, "aa-status")
	if err == nil {
		return appArmorStatusFromOutput("aa-status", string(output))
	}
	if !isMissingCommandError(err) {
		status := appArmorStatusFromOutput("aa-status", err.Error())
		if status.State != "missing" {
			return status
		}
	}

	output, err = ctx.Runner.Run(ctx.Context, "systemctl", "status", "apparmor")
	if err == nil {
		return appArmorStatusFromOutput("apparmor", string(output))
	}
	if isMissingCommandError(err) || strings.Contains(strings.ToLower(err.Error()), "could not be found") {
		return appArmorStatus{State: "missing", Evidence: "apparmor=not_installed"}
	}

	status := appArmorStatusFromOutput("apparmor", err.Error())
	if status.State == "missing" {
		status.State = "inactive"
		status.Evidence = "apparmor=not_active"
	}
	return status
}

func appArmorStatusFromOutput(source, output string) appArmorStatus {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "apparmor module is loaded") ||
		strings.Contains(lower, "profiles are loaded") ||
		strings.Contains(lower, "active: active"):
		return appArmorStatus{State: "active", Evidence: source + "=active"}
	case strings.Contains(lower, "apparmor module is not loaded") ||
		strings.Contains(lower, "not loaded") ||
		strings.Contains(lower, "active: inactive") ||
		strings.Contains(lower, "active: failed"):
		return appArmorStatus{State: "inactive", Evidence: source + "=inactive"}
	case strings.Contains(lower, "not-found") ||
		strings.Contains(lower, "could not be found") ||
		strings.Contains(lower, "not installed"):
		return appArmorStatus{State: "missing", Evidence: source + "=not_installed"}
	default:
		return appArmorStatus{State: "inactive", Evidence: source + "=not_confirmed"}
	}
}

type authLogCounts struct {
	FoundLog bool
	Accepted int
	Failed   int
}

func recentSSHLoginCounts(paths []string, now time.Time) (authLogCounts, error) {
	counts := authLogCounts{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return counts, err
		}

		counts.FoundLog = true
		addAuthLogCounts(&counts, string(data), now)
	}
	return counts, nil
}

func addAuthLogCounts(counts *authLogCounts, content string, now time.Time) {
	cutoff := now.AddDate(0, 0, -60)
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "sshd") {
			continue
		}
		timestamp, ok := parseSyslogTimestamp(line, now)
		if !ok || timestamp.Before(cutoff) || timestamp.After(now.Add(24*time.Hour)) {
			continue
		}

		lower := strings.ToLower(line)
		if strings.Contains(lower, "accepted ") {
			counts.Accepted++
			continue
		}
		if strings.Contains(lower, "failed password") ||
			strings.Contains(lower, "failed publickey") ||
			strings.Contains(lower, "failed none") ||
			strings.Contains(lower, "authentication failure") {
			counts.Failed++
		}
	}
}

func parseSyslogTimestamp(line string, now time.Time) (time.Time, bool) {
	if len(line) < len("Jan  2 15:04:05") {
		return time.Time{}, false
	}

	parsed, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], now.Location())
	if err != nil {
		return time.Time{}, false
	}

	timestamp := time.Date(now.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, now.Location())
	if timestamp.After(now.Add(24 * time.Hour)) {
		timestamp = timestamp.AddDate(-1, 0, 0)
	}
	return timestamp, true
}

func nprocLimitEntries() ([]string, []string) {
	files, err := limitsFiles()
	if err != nil {
		return nil, []string{"limits=glob_error"}
	}

	entries := []string{}
	readErrors := []string{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			readErrors = append(readErrors, limitsEvidenceName(path)+"=read_error")
			continue
		}
		entries = append(entries, nprocLimitLines(path, string(data))...)
	}

	return unique(entries), unique(readErrors)
}

func limitsFiles() ([]string, error) {
	files := []string{}
	if _, err := os.Stat(limitsConfPath); err == nil {
		files = append(files, limitsConfPath)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	matches, err := filepath.Glob(filepath.Join(limitsDropInPath, "*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, path)
	}

	return files, nil
}

func nprocLimitLines(path, content string) []string {
	entries := []string{}
	name := limitsEvidenceName(path)
	for _, line := range strings.Split(content, "\n") {
		line = stripSudoersComment(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		for i, field := range fields {
			if field != "nproc" {
				continue
			}
			value := "set"
			if len(fields) > i+1 {
				value = fields[i+1]
			}
			entries = append(entries, name+":nproc="+value)
			break
		}
	}
	return entries
}

func limitsEvidenceName(path string) string {
	base := filepath.Base(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "limits"
	}
	return base
}

type processInfo struct {
	User    string
	PID     string
	CPU     float64
	Memory  float64
	Command string
}

func parsePSAux(output string) []processInfo {
	processes := []processInfo{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToUpper(line), "USER ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		memory, _ := strconv.ParseFloat(fields[3], 64)
		processes = append(processes, processInfo{
			User:    fields[0],
			PID:     fields[1],
			CPU:     cpu,
			Memory:  memory,
			Command: strings.Join(fields[10:], " "),
		})
	}
	return processes
}

func topProcesses(processes []processInfo, limit int) []processInfo {
	out := append([]processInfo(nil), processes...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CPU == out[j].CPU {
			return out[i].Memory > out[j].Memory
		}
		return out[i].CPU > out[j].CPU
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func suspiciousRootProcesses(processes []processInfo) []processInfo {
	suspicious := []processInfo{}
	for _, process := range processes {
		if process.User != "root" {
			continue
		}
		command := strings.ToLower(process.Command)
		if strings.Contains(command, "/tmp/") ||
			strings.Contains(command, "/dev/shm/") ||
			strings.Contains(command, "(deleted)") ||
			strings.Contains(command, " deleted") {
			suspicious = append(suspicious, process)
		}
	}
	return suspicious
}

func processEvidence(processes []processInfo, limit int) string {
	if len(processes) == 0 {
		return "none"
	}
	if len(processes) > limit {
		processes = processes[:limit]
	}

	values := []string{}
	for _, process := range processes {
		values = append(values, fmt.Sprintf("%s:%s:cpu=%.1f:mem=%.1f:%s", process.User, process.PID, process.CPU, process.Memory, compactCommand(process.Command)))
	}
	return strings.Join(values, "; ")
}

func compactCommand(command string) string {
	command = strings.Join(strings.Fields(command), " ")
	if len(command) > 80 {
		return command[:77] + "..."
	}
	return command
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
