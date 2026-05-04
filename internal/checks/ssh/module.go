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
	result.Summary = "Could not read effective sshd configuration."
	result.Error = err.Error()
	result.Remediation = "Run secscan with privileges that can execute sshd -T, then retry the audit."
	return result
}

func missingKeyResult(id, title, key string) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, checks.SeverityMedium, checks.StatusError)
	result.Summary = "Could not find expected sshd option in effective configuration."
	result.Evidence = key + " missing from sshd -T output"
	result.Remediation = "Verify the local OpenSSH server version and sshd -T output."
	return result
}

type checkPermitRootLogin struct {
	config *EffectiveConfig
}

func (c checkPermitRootLogin) ID() string {
	return "sshd.permit_root_login"
}

func (c checkPermitRootLogin) Title() string {
	return "PermitRootLogin is not enabled"
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
	result.Evidence = "permitrootlogin=" + value
	result.Remediation = "Set PermitRootLogin no in sshd_config and reload sshd."

	if value == "yes" {
		result.Status = checks.StatusFail
		result.Summary = "Root login over SSH is enabled."
		return result
	}

	result.Summary = "Root login over SSH is not explicitly enabled."
	return result
}

type checkPasswordAuthentication struct {
	config *EffectiveConfig
}

func (c checkPasswordAuthentication) ID() string {
	return "sshd.password_authentication"
}

func (c checkPasswordAuthentication) Title() string {
	return "PasswordAuthentication is not enabled"
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
	result.Evidence = "passwordauthentication=" + value
	result.Remediation = "Prefer key-based SSH login and set PasswordAuthentication no when operationally possible."

	if value == "yes" {
		result.Status = checks.StatusWarn
		result.Summary = "Password based SSH login is enabled."
		return result
	}

	result.Summary = "Password based SSH login is not enabled."
	return result
}

type checkPermitEmptyPasswords struct {
	config *EffectiveConfig
}

func (c checkPermitEmptyPasswords) ID() string {
	return "sshd.permit_empty_passwords"
}

func (c checkPermitEmptyPasswords) Title() string {
	return "PermitEmptyPasswords is disabled"
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
	result.Evidence = "permitemptypasswords=" + value
	result.Remediation = "Set PermitEmptyPasswords no in sshd_config and reload sshd."

	if value != "no" {
		result.Status = checks.StatusFail
		result.Summary = "SSH accounts with empty passwords are permitted."
		return result
	}

	result.Summary = "SSH accounts with empty passwords are not permitted."
	return result
}
