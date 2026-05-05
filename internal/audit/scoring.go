package audit

import (
	"math"
	"sort"

	"secscan/internal/checks"
)

func PrepareReport(report *Report) {
	report.Summary = emptyStatusSummary()
	report.SeverityCounts = emptySeverityCounts()
	report.SeverityIssues = emptySeverityCounts()
	report.TopFindings = []checks.Result{}
	report.ClientFindings = []checks.Result{}
	report.AdminFindings = []checks.Result{}
	report.Inventory = Inventory{
		Services: report.RunningServices,
		Modules:  report.Modules,
	}

	for i := range report.Results {
		report.Results[i].Normalize()
		result := report.Results[i]

		report.Summary[string(result.Status)]++
		if _, ok := report.SeverityCounts[string(result.Severity)]; ok {
			report.SeverityCounts[string(result.Severity)]++
		}

		if isRisk(result) {
			if _, ok := report.SeverityIssues[string(result.Severity)]; ok {
				report.SeverityIssues[string(result.Severity)]++
			}
			if !result.HiddenInClientReport {
				report.ClientFindings = append(report.ClientFindings, result)
			}
		}

		if isAdminFinding(result) {
			report.AdminFindings = append(report.AdminFindings, result)
		}
	}

	sortFindings(report.ClientFindings)
	sortFindings(report.AdminFindings)
	report.TopFindings = topFindings(report.Results, 10)
	report.Score = calculateScore(report.Results)
}

func emptyStatusSummary() map[string]int {
	return map[string]int{
		string(checks.StatusPass):          0,
		string(checks.StatusWarn):          0,
		string(checks.StatusFail):          0,
		string(checks.StatusInfo):          0,
		string(checks.StatusError):         0,
		string(checks.StatusNotApplicable): 0,
	}
}

func emptySeverityCounts() map[string]int {
	return map[string]int{
		string(checks.SeverityCritical): 0,
		string(checks.SeverityHigh):     0,
		string(checks.SeverityMedium):   0,
		string(checks.SeverityLow):      0,
		string(checks.SeverityInfo):     0,
	}
}

func calculateScore(results []checks.Result) int {
	penalty := 0.0
	hasWarn := false
	for _, result := range results {
		if result.Status == checks.StatusWarn {
			hasWarn = true
		}
		penalty += scorePenalty(result)
	}

	score := int(math.Round(100 - penalty))
	if hasWarn && score > 90 {
		score = 90
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}

	return score
}

func topFindings(results []checks.Result, limit int) []checks.Result {
	findings := []checks.Result{}
	for _, result := range results {
		if isRisk(result) {
			findings = append(findings, result)
		}
	}

	sortFindings(findings)
	if len(findings) > limit {
		findings = findings[:limit]
	}

	return findings
}

func sortFindings(findings []checks.Result) {
	sort.SliceStable(findings, func(i, j int) bool {
		leftSeverity := severityRank(findings[i].Severity)
		rightSeverity := severityRank(findings[j].Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}

		leftStatus := statusRank(findings[i].Status)
		rightStatus := statusRank(findings[j].Status)
		if leftStatus != rightStatus {
			return leftStatus > rightStatus
		}

		return false
	})
}

func isRisk(result checks.Result) bool {
	return result.Status == checks.StatusFail || result.Status == checks.StatusWarn
}

func isAdminFinding(result checks.Result) bool {
	switch result.Status {
	case checks.StatusFail, checks.StatusWarn, checks.StatusError, checks.StatusPass:
		return true
	default:
		return false
	}
}

func scorePenalty(result checks.Result) float64 {
	if result.Status == checks.StatusFail {
		return failPenalty(result.Severity)
	}
	if result.Status == checks.StatusWarn {
		return warnPenalty(result.Severity)
	}

	return 0
}

func failPenalty(severity checks.Severity) float64 {
	switch severity {
	case checks.SeverityCritical:
		return 25
	case checks.SeverityHigh:
		return 15
	case checks.SeverityMedium:
		return 8
	case checks.SeverityLow:
		return 3
	default:
		return 0
	}
}

func warnPenalty(severity checks.Severity) float64 {
	switch severity {
	case checks.SeverityCritical:
		return 12.5
	case checks.SeverityHigh:
		return 7.5
	case checks.SeverityMedium:
		return 5
	case checks.SeverityLow:
		return 2
	default:
		return 0
	}
}

func severityRank(severity checks.Severity) int {
	switch severity {
	case checks.SeverityCritical:
		return 5
	case checks.SeverityHigh:
		return 4
	case checks.SeverityMedium:
		return 3
	case checks.SeverityLow:
		return 2
	case checks.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func statusRank(status checks.Status) int {
	switch status {
	case checks.StatusFail:
		return 3
	case checks.StatusWarn:
		return 2
	default:
		return 1
	}
}
