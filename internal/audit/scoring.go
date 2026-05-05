package audit

import (
	"math"
	"sort"

	"secscan/internal/checks"
)

func PrepareReport(report *Report) {
	report.Summary = emptyStatusSummary()
	report.SeverityCounts = emptySeverityCounts()
	report.AdminFindings = make([]checks.Result, 0, len(report.Results))
	report.ClientFindings = []checks.Result{}

	for i := range report.Results {
		report.Results[i].Normalize()
		result := report.Results[i]
		report.Summary[string(result.Status)]++
		report.AdminFindings = append(report.AdminFindings, result)

		if isRisk(result) {
			report.SeverityCounts[string(result.Severity)]++
			if !result.HiddenInClientReport {
				report.ClientFindings = append(report.ClientFindings, result)
			}
		}
	}

	report.Score = calculateScore(report.Results)
	report.TopFindings = topFindings(report.Results, 10)
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
	}
}

func calculateScore(results []checks.Result) int {
	penalty := 0.0
	for _, result := range results {
		penalty += scorePenalty(result)
	}

	score := int(math.Round(100 - penalty))
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

	sort.SliceStable(findings, func(i, j int) bool {
		left := scorePenalty(findings[i])
		right := scorePenalty(findings[j])
		if left != right {
			return left > right
		}

		return findings[i].Title < findings[j].Title
	})

	if len(findings) > limit {
		findings = findings[:limit]
	}

	return findings
}

func isRisk(result checks.Result) bool {
	return result.Status == checks.StatusFail || result.Status == checks.StatusWarn
}

func scorePenalty(result checks.Result) float64 {
	base := severityPenalty(result.Severity)
	if result.Status == checks.StatusWarn {
		return base / 2
	}
	if result.Status == checks.StatusFail {
		return base
	}

	return 0
}

func severityPenalty(severity checks.Severity) float64 {
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
