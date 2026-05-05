package audit

import (
	"context"
	"time"

	"secscan/internal/checks"
	"secscan/internal/checks/linux"
	"secscan/internal/checks/nginx"
	"secscan/internal/checks/service"
	"secscan/internal/checks/ssh"
	"secscan/internal/execx"
	"secscan/internal/system"
)

const (
	ToolName = "secscan"
	Version  = "0.1.0"
)

type ModuleReport struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	Selected bool   `json:"selected"`
}

type Report struct {
	Tool            string            `json:"tool"`
	Version         string            `json:"version"`
	GeneratedAt     string            `json:"generated_at"`
	Host            system.Info       `json:"host"`
	RunningServices []system.Service  `json:"running_services"`
	Modules         []ModuleReport    `json:"modules"`
	Results         []checks.Result   `json:"results"`
	Errors          []string          `json:"errors,omitempty"`
	Summary         map[string]int    `json:"summary,omitempty"`
	SeverityCounts  map[string]int    `json:"severity_counts"`
	Score           int               `json:"score"`
	TopFindings     []checks.Result   `json:"top_findings"`
	ClientFindings  []checks.Result   `json:"client_findings"`
	AdminFindings   []checks.Result   `json:"admin_findings"`
	Meta            map[string]string `json:"meta,omitempty"`
}

type Options struct {
	AllModules bool
}

func DefaultRegistry() checks.Registry {
	modules := []checks.Module{
		linux.NewModule(),
		ssh.NewModule(),
		nginx.NewModule(),
	}
	modules = append(modules, service.DefaultModules()...)

	return checks.NewRegistry(modules...)
}

func Run(ctx context.Context, runner execx.Runner, registry checks.Registry) Report {
	return RunWithOptions(ctx, runner, registry, Options{})
}

func RunWithOptions(ctx context.Context, runner execx.Runner, registry checks.Registry, options Options) Report {
	host := system.DetectInfo()
	services, err := system.RunningServices(ctx, runner)
	if services == nil {
		services = []system.Service{}
	}

	report := Report{
		Tool:            ToolName,
		Version:         Version,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Host:            host,
		RunningServices: services,
		Modules:         []ModuleReport{},
		Results:         []checks.Result{},
		Meta: map[string]string{
			"audit_mode": auditMode(options),
		},
	}

	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}

	checkCtx := checks.Context{
		Context:  ctx,
		Runner:   runner,
		Host:     host,
		Services: services,
	}

	for _, module := range registry.Modules() {
		detected := module.Detect(checkCtx)
		selected := detected || options.AllModules
		report.Modules = append(report.Modules, ModuleReport{
			ID:       module.ID(),
			Name:     module.Name(),
			Detected: detected,
			Selected: selected,
		})

		if !selected {
			continue
		}

		for _, check := range module.Checks() {
			result := check.Run(checkCtx)
			report.Results = append(report.Results, result)
		}
	}

	PrepareReport(&report)
	return report
}

func Detect(ctx context.Context, runner execx.Runner, registry checks.Registry) Report {
	report := Run(ctx, runner, registry)
	report.Results = []checks.Result{}
	report.Summary = nil
	report.SeverityCounts = nil
	report.Score = 0
	report.TopFindings = nil
	report.ClientFindings = nil
	report.AdminFindings = nil
	return report
}

func auditMode(options Options) string {
	if options.AllModules {
		return "all_modules"
	}

	return "detected_modules"
}
