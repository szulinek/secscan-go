package checks

import (
	"context"

	"secscan/internal/execx"
	"secscan/internal/system"
)

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusWarn  Status = "warn"
	StatusInfo  Status = "info"
	StatusError Status = "error"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
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
	ID          string   `json:"id"`
	ModuleID    string   `json:"module_id"`
	Service     string   `json:"service"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Error       string   `json:"error,omitempty"`
}

func NewResult(id, moduleID, service, title string, severity Severity, status Status) Result {
	return Result{
		ID:       id,
		ModuleID: moduleID,
		Service:  service,
		Title:    title,
		Severity: severity,
		Status:   status,
	}
}
