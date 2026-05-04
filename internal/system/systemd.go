package system

import (
	"context"
	"strings"

	"secscan/internal/execx"
)

type Service struct {
	Unit        string `json:"unit"`
	Load        string `json:"load,omitempty"`
	Active      string `json:"active,omitempty"`
	Sub         string `json:"sub,omitempty"`
	Description string `json:"description,omitempty"`
}

func RunningServices(ctx context.Context, runner execx.Runner) ([]Service, error) {
	output, err := runner.Run(
		ctx,
		"systemctl",
		"list-units",
		"--type=service",
		"--state=running",
		"--no-legend",
		"--no-pager",
		"--plain",
	)
	if err != nil {
		return nil, err
	}

	return ParseSystemctlListUnits(string(output)), nil
}

func ParseSystemctlListUnits(output string) []Service {
	var services []Service
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}

		services = append(services, Service{
			Unit:        fields[0],
			Load:        fields[1],
			Active:      fields[2],
			Sub:         fields[3],
			Description: description,
		})
	}

	return services
}

func HasRunningService(services []Service, names ...string) bool {
	expected := map[string]struct{}{}
	for _, name := range names {
		expected[name] = struct{}{}
	}

	for _, service := range services {
		if _, ok := expected[service.Unit]; ok {
			return true
		}
	}

	return false
}
