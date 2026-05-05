package ssh

import (
	"strings"
	"sync"

	"secscan/internal/checks"
	"secscan/internal/system"
)

const (
	moduleID = "sshd"
	service  = "sshd"
)

type Module struct {
	config *EffectiveConfig
}

func NewModule() *Module {
	return &Module{config: &EffectiveConfig{}}
}

func (m *Module) ID() string {
	return moduleID
}

func (m *Module) Name() string {
	return "OpenSSH server"
}

func (m *Module) Detect(ctx checks.Context) bool {
	return system.HasRunningService(ctx.Services, "ssh.service", "sshd.service")
}

func (m *Module) Checks() []checks.Check {
	return []checks.Check{
		checkPermitRootLogin{config: m.config},
		checkPasswordAuthentication{config: m.config},
		checkPermitEmptyPasswords{config: m.config},
	}
}

type EffectiveConfig struct {
	once   sync.Once
	values map[string]string
	err    error
}

func (c *EffectiveConfig) Values(ctx checks.Context) (map[string]string, error) {
	c.once.Do(func() {
		output, err := ctx.Runner.Run(ctx.Context, "sshd", "-T")
		if err != nil {
			c.err = err
			return
		}

		c.values = parseSSHDConfig(string(output))
	})

	return c.values, c.err
}

func parseSSHDConfig(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}

		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToLower(strings.TrimSpace(value))
		if key != "" {
			values[key] = value
		}
	}

	return values
}

func configErrorResult(id, title string, err error) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, checks.SeverityHigh, checks.StatusError)
	result.Category = checks.CategorySSH
	result.Summary = "Could not read effective sshd configuration."
	result.Impact = "SSH hardening could not be verified, so remote access risk is unknown."
	result.Recommendation = "Run secscan with privileges that can execute sshd -T, then retry the audit."
	result.Remediation = result.Recommendation
	result.ClientSummary = "SSH security settings could not be verified."
	result.AdminDetails = "Command failed: sshd -T\n" + err.Error()
	result.HiddenInClientReport = true
	result.Error = err.Error()
	return result
}

func missingKeyResult(id, title, key string) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, checks.SeverityMedium, checks.StatusError)
	result.Category = checks.CategorySSH
	result.Summary = "Could not find expected sshd option in effective configuration."
	result.Impact = "The SSH hardening state could not be reliably assessed."
	result.Recommendation = "Verify the local OpenSSH server version and sshd -T output."
	result.Remediation = result.Recommendation
	result.Evidence = key + " missing from sshd -T output"
	result.ClientSummary = "SSH security settings could not be verified."
	result.AdminDetails = "Expected key missing from effective sshd configuration: " + key
	result.HiddenInClientReport = true
	return result
}

type checkPermitRootLogin struct {
	config *EffectiveConfig
}

func (c checkPermitRootLogin) ID() string {
	return "sshd.permit_root_login"
}

func (c checkPermitRootLogin) Title() string {
	return "PermitRootLogin state"
}

func (c checkPermitRootLogin) Run(ctx checks.Context) checks.Result {
	values, err := c.config.Values(ctx)
	if err != nil {
		return configErrorResult(c.ID(), c.Title(), err)
	}

	value, ok := values["permitrootlogin"]
	if !ok {
		return missingKeyResult(c.ID(), c.Title(), "permitrootlogin")
	}

	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Category = checks.CategorySSH
	result.Evidence = "permitrootlogin=" + value
	result.Impact = "Direct root SSH access increases the blast radius of credential theft and brute-force attacks."
	result.Recommendation = "Set PermitRootLogin no in sshd_config and reload sshd."
	result.Remediation = result.Recommendation
	result.AdminDetails = "Checked effective OpenSSH configuration using sshd -T."

	if value == "yes" {
		result.Title = "PermitRootLogin is enabled"
		result.Status = checks.StatusFail
		result.Summary = "Root login over SSH is enabled."
		result.ClientSummary = "Direct root login over SSH is enabled."
		return result
	}

	result.Title = "PermitRootLogin is disabled"
	result.Summary = "Root login over SSH is not explicitly enabled."
	result.ClientSummary = "Direct root login over SSH is not enabled."
	return result
}

type checkPasswordAuthentication struct {
	config *EffectiveConfig
}

func (c checkPasswordAuthentication) ID() string {
	return "sshd.password_authentication"
}

func (c checkPasswordAuthentication) Title() string {
	return "PasswordAuthentication state"
}

func (c checkPasswordAuthentication) Run(ctx checks.Context) checks.Result {
	values, err := c.config.Values(ctx)
	if err != nil {
		return configErrorResult(c.ID(), c.Title(), err)
	}

	value, ok := values["passwordauthentication"]
	if !ok {
		return missingKeyResult(c.ID(), c.Title(), "passwordauthentication")
	}

	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Category = checks.CategorySSH
	result.Evidence = "passwordauthentication=" + value
	result.Impact = "Password SSH login increases exposure to brute-force and credential reuse attacks."
	result.Recommendation = "Prefer key-based SSH login and set PasswordAuthentication no when operationally possible."
	result.Remediation = result.Recommendation
	result.AdminDetails = "Checked effective OpenSSH configuration using sshd -T."

	if value == "yes" {
		result.Title = "PasswordAuthentication is enabled"
		result.Status = checks.StatusWarn
		result.Summary = "Password based SSH login is enabled."
		result.ClientSummary = "SSH password login is enabled."
		return result
	}

	result.Title = "PasswordAuthentication is disabled"
	result.Summary = "Password based SSH login is disabled."
	result.ClientSummary = "SSH password login is disabled."
	return result
}

type checkPermitEmptyPasswords struct {
	config *EffectiveConfig
}

func (c checkPermitEmptyPasswords) ID() string {
	return "sshd.permit_empty_passwords"
}

func (c checkPermitEmptyPasswords) Title() string {
	return "PermitEmptyPasswords state"
}

func (c checkPermitEmptyPasswords) Run(ctx checks.Context) checks.Result {
	values, err := c.config.Values(ctx)
	if err != nil {
		return configErrorResult(c.ID(), c.Title(), err)
	}

	value, ok := values["permitemptypasswords"]
	if !ok {
		return missingKeyResult(c.ID(), c.Title(), "permitemptypasswords")
	}

	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Category = checks.CategorySSH
	result.Evidence = "permitemptypasswords=" + value
	result.Impact = "Accounts without passwords create an immediate unauthorized-access risk if reachable through SSH."
	result.Recommendation = "Set PermitEmptyPasswords no in sshd_config and reload sshd."
	result.Remediation = result.Recommendation
	result.AdminDetails = "Checked effective OpenSSH configuration using sshd -T."

	if value != "no" {
		result.Title = "PermitEmptyPasswords is enabled"
		result.Status = checks.StatusFail
		result.Summary = "SSH accounts with empty passwords are permitted."
		result.ClientSummary = "SSH would allow accounts with empty passwords."
		return result
	}

	result.Title = "PermitEmptyPasswords is disabled"
	result.Summary = "SSH accounts with empty passwords are not permitted."
	result.ClientSummary = "SSH accounts with empty passwords are not permitted."
	return result
}
