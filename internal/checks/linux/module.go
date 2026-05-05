package linux

import (
	"os"
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
		checkUnattendedUpgrades{},
		checkFirewallDetected{},
	}
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

type checkFirewallDetected struct{}

func (c checkFirewallDetected) ID() string {
	return "linux.firewall_detected"
}

func (c checkFirewallDetected) Title() string {
	return "Host firewall is present"
}

func (c checkFirewallDetected) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, "firewall", c.Title(), checks.SeverityHigh, checks.StatusFail)
	result.Category = checks.CategoryFirewall
	result.Impact = "Without a detected host firewall, exposed services may be reachable more broadly than intended."
	result.Recommendation = "Enable and verify a firewall layer such as CSF/LFD, nftables, iptables, or UFW."
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

	signals := firewallSignals(ctx)
	result.Evidence = strings.Join(signals, "; ")
	result.AdminDetails = "Detection looked for CSF/LFD, nftables, iptables, and UFW using running services, known config paths, and read-only command probes."

	if len(signals) > 0 {
		result.Status = checks.StatusPass
		result.Summary = "A host firewall signal was detected."
		result.ClientSummary = "A host-level firewall appears to be present."
		return result
	}

	result.Evidence = "no firewall signal detected"
	result.Summary = "No host firewall signal was detected."
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

func firewallSignals(ctx checks.Context) []string {
	signals := []string{}
	serviceNames := []string{"csf.service", "lfd.service", "nftables.service", "ufw.service", "firewalld.service"}
	for _, service := range ctx.Services {
		for _, expected := range serviceNames {
			if service.Unit == expected {
				signals = append(signals, "running_service="+service.Unit)
			}
		}
	}

	paths := []string{"/etc/csf/csf.conf", "/usr/sbin/csf", "/usr/sbin/lfd", "/etc/ufw/ufw.conf"}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			signals = append(signals, "path_exists="+path)
		}
	}

	if output, err := ctx.Runner.Run(ctx.Context, "ufw", "status"); err == nil && strings.Contains(strings.ToLower(string(output)), "status: active") {
		signals = append(signals, "ufw=status active")
	}
	if output, err := ctx.Runner.Run(ctx.Context, "nft", "list", "ruleset"); err == nil && strings.TrimSpace(string(output)) != "" {
		signals = append(signals, "nft=ruleset present")
	}
	if output, err := ctx.Runner.Run(ctx.Context, "iptables", "-S"); err == nil && iptablesLooksConfigured(string(output)) {
		signals = append(signals, "iptables=rules present")
	}

	return unique(signals)
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
