package audit

import (
	"context"
	"time"

	"secscan/internal/checks"
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
	Meta            map[string]string `json:"meta,omitempty"`
}

func DefaultRegistry() checks.Registry {
	return checks.NewRegistry(
		ssh.NewModule(),
	)
}

func Run(ctx context.Context, runner execx.Runner, registry checks.Registry) Report {
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
		Summary: map[string]int{
			string(checks.StatusPass):  0,
			string(checks.StatusWarn):  0,
			string(checks.StatusFail):  0,
			string(checks.StatusInfo):  0,
			string(checks.StatusError): 0,
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
		report.Modules = append(report.Modules, ModuleReport{
			ID:       module.ID(),
			Name:     module.Name(),
			Detected: detected,
		})

		if !detected {
			continue
		}

		for _, check := range module.Checks() {
			result := check.Run(checkCtx)
			report.Results = append(report.Results, result)
			report.Summary[string(result.Status)]++
		}
	}

	return report
}

func Detect(ctx context.Context, runner execx.Runner, registry checks.Registry) Report {
	report := Run(ctx, runner, registry)
	report.Results = []checks.Result{}
	report.Summary = nil
	return report
}
