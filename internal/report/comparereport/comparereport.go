package comparereport

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"

	"secscan/internal/audit"
	"secscan/internal/checks"
)

type Report struct {
	PreviousScore int `json:"previous_score"`
	CurrentScore  int `json:"current_score"`
	ScoreDelta    int `json:"score_delta"`

	SeverityCountsDelta map[string]int `json:"severity_counts_delta"`
	SeverityIssuesDelta map[string]int `json:"severity_issues_delta"`
	ModuleDelta         []ModuleDelta  `json:"module_delta"`

	NewFindings      []checks.Result  `json:"new_findings"`
	ResolvedFindings []checks.Result  `json:"resolved_findings"`
	ChangedFindings  []ChangedFinding `json:"changed_findings"`

	Previous audit.Report `json:"-"`
	Current  audit.Report `json:"-"`
}

type ChangedFinding struct {
	ID              string        `json:"id"`
	Previous        checks.Result `json:"previous"`
	Current         checks.Result `json:"current"`
	StatusChanged   bool          `json:"status_changed"`
	SeverityChanged bool          `json:"severity_changed"`
	EvidenceChanged bool          `json:"evidence_changed"`
}

type ModuleDelta struct {
	ModuleID string `json:"module_id"`

	Previous audit.ModuleSummary `json:"previous"`
	Current  audit.ModuleSummary `json:"current"`

	FailDelta int `json:"fail_delta"`
	WarnDelta int `json:"warn_delta"`
	PassDelta int `json:"pass_delta"`
}

func Compare(previous, current audit.Report) Report {
	audit.PrepareReport(&previous)
	audit.PrepareReport(&current)

	report := Report{
		PreviousScore:       previous.Score,
		CurrentScore:        current.Score,
		ScoreDelta:          current.Score - previous.Score,
		SeverityCountsDelta: mapDelta(previous.SeverityCounts, current.SeverityCounts),
		SeverityIssuesDelta: mapDelta(previous.SeverityIssues, current.SeverityIssues),
		ModuleDelta:         compareModules(previous.ModuleSummary, current.ModuleSummary),
		Previous:            previous,
		Current:             current,
	}

	oldByID := resultMap(previous.Results)
	newByID := resultMap(current.Results)

	for _, result := range current.Results {
		if result.ID == "" || !compareIssueStatus(result.Status) {
			continue
		}
		if _, ok := oldByID[result.ID]; !ok {
			report.NewFindings = append(report.NewFindings, result)
		}
	}

	for _, result := range previous.Results {
		if result.ID == "" || !compareIssueStatus(result.Status) {
			continue
		}
		if _, ok := newByID[result.ID]; !ok {
			report.ResolvedFindings = append(report.ResolvedFindings, result)
		}
	}

	for _, currentResult := range current.Results {
		if currentResult.ID == "" {
			continue
		}
		previousResult, ok := oldByID[currentResult.ID]
		if !ok || (!compareFindingStatus(previousResult.Status) && !compareFindingStatus(currentResult.Status)) {
			continue
		}

		changed := ChangedFinding{
			ID:              currentResult.ID,
			Previous:        previousResult,
			Current:         currentResult,
			StatusChanged:   previousResult.Status != currentResult.Status,
			SeverityChanged: previousResult.Severity != currentResult.Severity,
			EvidenceChanged: previousResult.Evidence != currentResult.Evidence,
		}
		if changed.StatusChanged || changed.SeverityChanged || changed.EvidenceChanged {
			report.ChangedFindings = append(report.ChangedFindings, changed)
		}
	}

	sortResults(report.NewFindings)
	sortResults(report.ResolvedFindings)
	sortChanged(report.ChangedFindings)
	return report
}

func Render(w io.Writer, previous, current audit.Report) error {
	return pageTemplate.Execute(w, buildView(Compare(previous, current)))
}

func mapDelta(previous, current map[string]int) map[string]int {
	keys := map[string]struct{}{}
	for key := range previous {
		keys[key] = struct{}{}
	}
	for key := range current {
		keys[key] = struct{}{}
	}

	delta := map[string]int{}
	for key := range keys {
		delta[key] = current[key] - previous[key]
	}
	return delta
}

func compareModules(previous, current []audit.ModuleSummary) []ModuleDelta {
	oldByID := moduleMap(previous)
	newByID := moduleMap(current)
	keys := []string{}
	seen := map[string]struct{}{}
	for _, summary := range previous {
		if summary.ModuleID == "" {
			continue
		}
		keys = append(keys, summary.ModuleID)
		seen[summary.ModuleID] = struct{}{}
	}
	for _, summary := range current {
		if summary.ModuleID == "" {
			continue
		}
		if _, ok := seen[summary.ModuleID]; ok {
			continue
		}
		keys = append(keys, summary.ModuleID)
	}
	sort.Strings(keys)

	deltas := make([]ModuleDelta, 0, len(keys))
	for _, moduleID := range keys {
		oldSummary := oldByID[moduleID]
		newSummary := newByID[moduleID]
		deltas = append(deltas, ModuleDelta{
			ModuleID:  moduleID,
			Previous:  oldSummary,
			Current:   newSummary,
			FailDelta: newSummary.Fail - oldSummary.Fail,
			WarnDelta: newSummary.Warn - oldSummary.Warn,
			PassDelta: newSummary.Pass - oldSummary.Pass,
		})
	}
	return deltas
}

func resultMap(results []checks.Result) map[string]checks.Result {
	byID := map[string]checks.Result{}
	for _, result := range results {
		if result.ID == "" {
			continue
		}
		byID[result.ID] = result
	}
	return byID
}

func moduleMap(summaries []audit.ModuleSummary) map[string]audit.ModuleSummary {
	byID := map[string]audit.ModuleSummary{}
	for _, summary := range summaries {
		if summary.ModuleID == "" {
			continue
		}
		byID[summary.ModuleID] = summary
	}
	return byID
}

func compareIssueStatus(status checks.Status) bool {
	switch status {
	case checks.StatusFail, checks.StatusWarn, checks.StatusError:
		return true
	default:
		return false
	}
}

func compareFindingStatus(status checks.Status) bool {
	switch status {
	case checks.StatusFail, checks.StatusWarn, checks.StatusError, checks.StatusPass:
		return true
	default:
		return false
	}
}

func sortResults(results []checks.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		leftSeverity := severityRank(results[i].Severity)
		rightSeverity := severityRank(results[j].Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}
		leftStatus := statusRank(results[i].Status)
		rightStatus := statusRank(results[j].Status)
		if leftStatus != rightStatus {
			return leftStatus > rightStatus
		}
		return results[i].ID < results[j].ID
	})
}

func sortChanged(findings []ChangedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		leftSeverity := severityRank(findings[i].Current.Severity)
		rightSeverity := severityRank(findings[j].Current.Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}
		leftStatus := statusRank(findings[i].Current.Status)
		rightStatus := statusRank(findings[j].Current.Status)
		if leftStatus != rightStatus {
			return leftStatus > rightStatus
		}
		return findings[i].ID < findings[j].ID
	})
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
		return 4
	case checks.StatusWarn:
		return 3
	case checks.StatusError:
		return 2
	case checks.StatusPass:
		return 1
	default:
		return 0
	}
}

type viewData struct {
	Compare Report
	Host    string
}

func buildView(report Report) viewData {
	return viewData{
		Compare: report,
		Host:    hostLabel(report.Current),
	}
}

func hostLabel(report audit.Report) string {
	ip := strings.TrimSpace(report.Host.PrimaryIP)
	if ip == "" && len(report.Host.IPAddresses) > 0 {
		ip = report.Host.IPAddresses[0]
	}
	if report.Host.Hostname != "" && ip != "" {
		return report.Host.Hostname + " / " + ip
	}
	if report.Host.Hostname != "" {
		return report.Host.Hostname
	}
	if ip != "" {
		return ip
	}
	return "unknown host"
}

var pageTemplate = template.Must(template.New("compare").Funcs(template.FuncMap{
	"delta":         deltaLabel,
	"deltaClass":    deltaClass,
	"dict":          dict,
	"severityClass": severityClass,
	"upper":         strings.ToUpper,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Audit Comparison</title>
  <style>
    :root { color-scheme: light; --bg: #f8fafc; --ink: #111827; --muted: #667085; --line: #e5e7eb; --panel: #fff; --green: #16a34a; --red: #dc2626; --yellow: #f59e0b; --blue: #2563eb; --shadow: 0 10px 24px rgba(15, 23, 42, .07); }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--ink); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    .page { max-width: 1120px; margin: 0 auto; padding: 40px 24px 64px; }
    .cover, .panel, .finding { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
    .cover { padding: 40px; margin-bottom: 28px; }
    .eyebrow { color: #475467; font-size: 12px; text-transform: uppercase; font-weight: 800; }
    h1 { margin: 10px 0 8px; font-size: 46px; line-height: 1.05; letter-spacing: 0; }
    h2 { margin: 34px 0 14px; font-size: 24px; letter-spacing: 0; }
    h3 { margin: 0 0 8px; font-size: 17px; letter-spacing: 0; }
    p { margin: 6px 0 0; color: var(--muted); }
    .score-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-top: 28px; }
    .score-box { border: 1px solid var(--line); border-radius: 8px; padding: 18px; background: #f9fafb; }
    .score-box span { color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; }
    .score-box strong { display: block; margin-top: 4px; font-size: 34px; }
    .delta-good { color: var(--green); } .delta-bad { color: var(--red); } .delta-flat { color: var(--muted); }
    .panel { padding: 22px; margin-bottom: 18px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 11px 10px; border-bottom: 1px solid var(--line); text-align: left; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .findings { display: grid; gap: 14px; }
    .finding { padding: 18px 20px; border-left-width: 6px; box-shadow: none; page-break-inside: avoid; }
    .finding.new { border-left-color: var(--red); background: #fff7f7; }
    .finding.resolved { border-left-color: var(--green); background: #f6fff9; }
    .finding.changed { border-left-color: var(--yellow); background: #fffbeb; }
    .badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .badge { display: inline-flex; align-items: center; min-height: 26px; padding: 3px 10px; border-radius: 999px; border: 1px solid var(--line); font-size: 12px; font-weight: 800; text-transform: uppercase; background: #fff; }
    .critical, .high { color: var(--red); border-color: #fecaca; } .medium { color: #b45309; border-color: #fde68a; } .low { color: var(--blue); border-color: #bfdbfe; } .info { color: var(--muted); }
    .empty { color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; padding: 18px; background: #fff; }
    .diff { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }
    .diff-box { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fff; overflow-wrap: anywhere; }
    .diff-box span { display: block; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; margin-bottom: 4px; }
    @media (max-width: 760px) { .score-grid, .diff { grid-template-columns: 1fr; } h1 { font-size: 34px; } .cover { padding: 28px; } }
  </style>
</head>
<body>
  <main class="page">
    <section class="cover">
      <div class="eyebrow">Security audit comparison</div>
      <h1>Security Change Report</h1>
      <p>{{ .Host }}</p>
      <div class="score-grid">
        <div class="score-box"><span>Previous score</span><strong>{{ .Compare.PreviousScore }}/100</strong></div>
        <div class="score-box"><span>Current score</span><strong>{{ .Compare.CurrentScore }}/100</strong></div>
        <div class="score-box"><span>Score delta</span><strong class="{{ deltaClass .Compare.ScoreDelta }}">{{ delta .Compare.ScoreDelta }}</strong></div>
      </div>
    </section>

    <h2>Score trend</h2>
    <section class="panel">
      <table>
        <thead><tr><th>Metric</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead>
        <tbody>
          <tr><td>Score</td><td>{{ .Compare.PreviousScore }}</td><td>{{ .Compare.CurrentScore }}</td><td class="{{ deltaClass .Compare.ScoreDelta }}">{{ delta .Compare.ScoreDelta }}</td></tr>
          {{ range $key, $value := .Compare.SeverityCountsDelta }}<tr><td>{{ $key }} severity count</td><td>{{ index $.Compare.Previous.SeverityCounts $key }}</td><td>{{ index $.Compare.Current.SeverityCounts $key }}</td><td>{{ delta $value }}</td></tr>{{ end }}
          {{ range $key, $value := .Compare.SeverityIssuesDelta }}<tr><td>{{ $key }} issue count</td><td>{{ index $.Compare.Previous.SeverityIssues $key }}</td><td>{{ index $.Compare.Current.SeverityIssues $key }}</td><td>{{ delta $value }}</td></tr>{{ end }}
        </tbody>
      </table>
    </section>

    <h2>Module trend</h2>
    <section class="panel">
      <table>
        <thead><tr><th>Module</th><th>Fail</th><th>Warn</th><th>Pass</th></tr></thead>
        <tbody>
          {{ range .Compare.ModuleDelta }}<tr><td>{{ .ModuleID }}</td><td>{{ delta .FailDelta }}</td><td>{{ delta .WarnDelta }}</td><td>{{ delta .PassDelta }}</td></tr>{{ end }}
        </tbody>
      </table>
    </section>

    <h2>New findings</h2>
    <section class="findings">
      {{ if .Compare.NewFindings }}{{ range .Compare.NewFindings }}{{ template "finding" dict "Kind" "new" "Finding" . }}{{ end }}{{ else }}<div class="empty">No new tracked findings.</div>{{ end }}
    </section>

    <h2>Resolved findings</h2>
    <section class="findings">
      {{ if .Compare.ResolvedFindings }}{{ range .Compare.ResolvedFindings }}{{ template "finding" dict "Kind" "resolved" "Finding" . }}{{ end }}{{ else }}<div class="empty">No resolved tracked findings.</div>{{ end }}
    </section>

    <h2>Changed findings</h2>
    <section class="findings">
      {{ if .Compare.ChangedFindings }}{{ range .Compare.ChangedFindings }}
      <article class="finding changed">
        <h3>{{ .Current.Title }}</h3>
        <p>{{ .Current.ClientSummary }}</p>
        <div class="badges"><span class="badge {{ severityClass .Current.Severity }}">{{ .Current.Severity }}</span><span class="badge">{{ .Current.Status }}</span></div>
        <div class="diff">
          <div class="diff-box"><span>Previous</span>Status: {{ .Previous.Status }}<br>Severity: {{ .Previous.Severity }}<br>Evidence: {{ .Previous.Evidence }}</div>
          <div class="diff-box"><span>Current</span>Status: {{ .Current.Status }}<br>Severity: {{ .Current.Severity }}<br>Evidence: {{ .Current.Evidence }}</div>
        </div>
      </article>
      {{ end }}{{ else }}<div class="empty">No changed tracked findings.</div>{{ end }}
    </section>
  </main>
</body>
</html>

{{ define "finding" }}
<article class="finding {{ .Kind }}">
  <h3>{{ .Finding.Title }}</h3>
  <p>{{ .Finding.ClientSummary }}</p>
  <div class="badges"><span class="badge {{ severityClass .Finding.Severity }}">{{ .Finding.Severity }}</span><span class="badge">{{ .Finding.Status }}</span><span class="badge">{{ .Finding.ModuleID }}</span></div>
  {{ if .Finding.Evidence }}<p>Evidence: {{ .Finding.Evidence }}</p>{{ end }}
</article>
{{ end }}
`))

func deltaLabel(value int) string {
	if value > 0 {
		return "+" + strconv.Itoa(value)
	}
	return strconv.Itoa(value)
}

func deltaClass(value int) string {
	if value > 0 {
		return "delta-good"
	}
	if value < 0 {
		return "delta-bad"
	}
	return "delta-flat"
}

func severityClass(severity checks.Severity) string {
	if severity == "" {
		return "info"
	}
	return string(severity)
}

func dict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict expects key-value pairs")
	}
	out := map[string]any{}
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict key must be a string")
		}
		out[key] = values[i+1]
	}
	return out, nil
}
