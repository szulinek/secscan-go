package nginx

import (
	"os"
	"regexp"
	"strings"

	"secscan/internal/checks"
)

const (
	moduleID = "nginx"
	service  = "nginx"
)

type Module struct{}

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
	return []checks.Check{
		checkServiceDetected{},
		checkServerTokens{},
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

type checkServerTokens struct{}

func (c checkServerTokens) ID() string {
	return "nginx.server_tokens_off"
}

func (c checkServerTokens) Title() string {
	return "server_tokens is disabled"
}

func (c checkServerTokens) Run(ctx checks.Context) checks.Result {
	result := checks.NewResult(c.ID(), moduleID, service, c.Title(), checks.SeverityLow, checks.StatusFail)
	result.Category = checks.CategoryWeb
	result.Impact = "Version disclosure makes fingerprinting easier for automated scanners and opportunistic attackers."
	result.Recommendation = "Set server_tokens off; in the nginx http/server context and reload nginx."
	result.ClientSummary = "Nginx may expose version information."

	detected, detectEvidence := detect(ctx)
	if !detected {
		result.Status = checks.StatusNotApplicable
		result.Severity = checks.SeverityInfo
		result.Summary = "Nginx was not detected; server_tokens check was skipped."
		result.Evidence = detectEvidence
		result.AdminDetails = "This check requires nginx to be installed or running."
		result.HiddenInClientReport = true
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "nginx", "-T")
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Could not read effective nginx configuration."
		result.Evidence = detectEvidence
		result.Error = err.Error()
		result.AdminDetails = "Command failed: nginx -T\n" + err.Error()
		result.HiddenInClientReport = true
		return result
	}

	setting := serverTokensSetting(string(output))
	result.Evidence = "server_tokens=" + setting
	result.AdminDetails = "Checked effective nginx configuration using nginx -T."

	if setting == "off" {
		result.Status = checks.StatusPass
		result.Summary = "Nginx server_tokens is disabled."
		result.ClientSummary = "Nginx version disclosure is disabled."
		return result
	}

	if setting == "on" {
		result.Summary = "Nginx server_tokens is explicitly enabled."
		return result
	}

	result.Summary = "Nginx server_tokens was not set to off; nginx defaults to exposing version tokens."
	result.Evidence = "server_tokens=default"
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

var serverTokensRE = regexp.MustCompile(`(?i)\bserver_tokens\s+(on|off)\s*;`)

func serverTokensSetting(config string) string {
	setting := "default"
	for _, line := range strings.Split(config, "\n") {
		line = stripComment(line)
		match := serverTokensRE.FindStringSubmatch(line)
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

func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}
