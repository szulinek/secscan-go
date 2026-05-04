package service

import (
	"os"
	pathmatch "path"
	"path/filepath"
	"strings"

	"secscan/internal/checks"
)

type Definition struct {
	ID              string
	Name            string
	Service         string
	UnitNames       []string
	UnitGlobs       []string
	DetectPaths     []string
	DetectPathGlobs []string
}

type Module struct {
	definition Definition
}

func New(definition Definition) Module {
	return Module{definition: definition}
}

func (m Module) ID() string {
	return m.definition.ID
}

func (m Module) Name() string {
	return m.definition.Name
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := m.detectWithEvidence(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	return []checks.Check{
		serviceDetectedCheck{module: m},
	}
}

func (m Module) serviceName() string {
	if m.definition.Service != "" {
		return m.definition.Service
	}

	return m.definition.ID
}

func (m Module) detectWithEvidence(ctx checks.Context) (bool, string) {
	if unit, ok := m.matchingUnit(ctx); ok {
		return true, "running_service=" + unit
	}

	if path, ok := firstExistingPath(m.definition.DetectPaths); ok {
		return true, "path_exists=" + path
	}

	if path, ok := firstGlobMatch(m.definition.DetectPathGlobs); ok {
		return true, "path_exists=" + path
	}

	return false, "detected=false"
}

func (m Module) matchingUnit(ctx checks.Context) (string, bool) {
	for _, service := range ctx.Services {
		unit := strings.ToLower(service.Unit)
		for _, expected := range m.definition.UnitNames {
			if unit == strings.ToLower(expected) {
				return service.Unit, true
			}
		}

		for _, pattern := range m.definition.UnitGlobs {
			matched, err := pathmatch.Match(strings.ToLower(pattern), unit)
			if err == nil && matched {
				return service.Unit, true
			}
		}
	}

	return "", false
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}

	return "", false
}

func firstGlobMatch(patterns []string) (string, bool) {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}

		return matches[0], true
	}

	return "", false
}

type serviceDetectedCheck struct {
	module Module
}

func (c serviceDetectedCheck) ID() string {
	return c.module.ID() + ".service_detected"
}

func (c serviceDetectedCheck) Title() string {
	return "Service detected"
}

func (c serviceDetectedCheck) Run(ctx checks.Context) checks.Result {
	detected, evidence := c.module.detectWithEvidence(ctx)
	result := checks.NewResult(
		c.ID(),
		c.module.ID(),
		c.module.serviceName(),
		c.Title(),
		checks.SeverityInfo,
		checks.StatusInfo,
	)
	result.Evidence = evidence

	if detected {
		result.Summary = c.module.Name() + " was detected."
		return result
	}

	result.Summary = c.module.Name() + " was not detected."
	return result
}
