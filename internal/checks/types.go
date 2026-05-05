package checks

import (
	"context"
	"strings"

	"secscan/internal/execx"
	"secscan/internal/system"
)

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusWarn          Status = "warn"
	StatusInfo          Status = "info"
	StatusError         Status = "error"
	StatusNotApplicable Status = "not_applicable"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Category string

const (
	CategorySystem     Category = "system"
	CategoryWeb        Category = "web"
	CategoryDatabase   Category = "database"
	CategoryCache      Category = "cache"
	CategorySSH        Category = "ssh"
	CategoryMail       Category = "mail"
	CategoryFirewall   Category = "firewall"
	CategoryCompliance Category = "compliance"
)

type Context struct {
	Context  context.Context
	Runner   execx.Runner
	Host     system.Info
	Services []system.Service
}

type Module interface {
	ID() string
	Name() string
	Detect(ctx Context) bool
	Checks() []Check
}

type Check interface {
	ID() string
	Title() string
	Run(ctx Context) Result
}

type Result struct {
	ID                   string   `json:"id"`
	ModuleID             string   `json:"module_id"`
	Service              string   `json:"service"`
	Title                string   `json:"title"`
	Category             Category `json:"category"`
	Severity             Severity `json:"severity"`
	Status               Status   `json:"status"`
	Summary              string   `json:"summary,omitempty"`
	Impact               string   `json:"impact,omitempty"`
	Recommendation       string   `json:"recommendation,omitempty"`
	Evidence             string   `json:"evidence,omitempty"`
	ClientSummary        string   `json:"client_summary,omitempty"`
	AdminDetails         string   `json:"admin_details,omitempty"`
	HiddenInClientReport bool     `json:"hidden_in_client_report"`
	Remediation          string   `json:"remediation,omitempty"`
	Error                string   `json:"error,omitempty"`
}

func NewResult(id, moduleID, service, title string, severity Severity, status Status) Result {
	return Result{
		ID:       id,
		ModuleID: moduleID,
		Service:  service,
		Title:    title,
		Category: CategorySystem,
		Severity: severity,
		Status:   status,
	}
}

func (r *Result) Normalize() {
	if r.Category == "" {
		r.Category = CategorySystem
	}
	if r.ClientSummary == "" {
		r.ClientSummary = r.Summary
	}
	if r.Recommendation == "" {
		r.Recommendation = r.Remediation
	}
	if r.Remediation == "" {
		r.Remediation = r.Recommendation
	}
	if r.AdminDetails == "" {
		parts := []string{}
		if r.Summary != "" {
			parts = append(parts, r.Summary)
		}
		if r.Evidence != "" {
			parts = append(parts, "Evidence: "+r.Evidence)
		}
		if r.Error != "" {
			parts = append(parts, "Error: "+r.Error)
		}
		r.AdminDetails = strings.Join(parts, "\n")
	}
}
