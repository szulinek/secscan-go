package batchreport

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/report/htmlreport"
)

type viewData struct {
	Title        string
	ReportType   string
	HostCount    int
	AverageScore int
	IssueCounts  map[string]int
	Hosts        []hostView
}

type hostView struct {
	HostLabel    string
	IPLabel      string
	Platform     string
	Score        int
	IssueCount   int
	IssueCounts  map[string]int
	TopFindings  []checks.Result
	ModuleCounts []audit.ModuleSummary
}

func LoadReports(inputDir string) ([]audit.Report, error) {
	pattern := filepath.Join(inputDir, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no JSON reports found in %s", inputDir)
	}

	reports := make([]audit.Report, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var report audit.Report
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if report.Meta == nil {
			report.Meta = map[string]string{}
		}
		report.Meta["source_file"] = filepath.Base(path)
		reports = append(reports, report)
	}

	return reports, nil
}

func Render(w io.Writer, reports []audit.Report, reportType htmlreport.Type) error {
	data := buildView(reports, reportType)
	return pageTemplate.Execute(w, data)
}

func buildView(reports []audit.Report, reportType htmlreport.Type) viewData {
	hosts := make([]hostView, 0, len(reports))
	totalScore := 0
	totalIssues := emptySeverityCounts()

	for _, report := range reports {
		audit.PrepareReport(&report)
		host := buildHostView(report, reportType)
		hosts = append(hosts, host)
		totalScore += report.Score
		for severity, count := range report.SeverityIssues {
			if _, ok := totalIssues[severity]; ok {
				totalIssues[severity] += count
			}
		}
	}

	averageScore := 0
	if len(hosts) > 0 {
		averageScore = totalScore / len(hosts)
	}

	title := "Security Audit Batch Report"
	if reportType == htmlreport.TypeAdmin {
		title = "Security Audit Batch Report - Admin"
	}

	return viewData{
		Title:        title,
		ReportType:   string(reportType),
		HostCount:    len(hosts),
		AverageScore: averageScore,
		IssueCounts:  totalIssues,
		Hosts:        hosts,
	}
}

func buildHostView(report audit.Report, reportType htmlreport.Type) hostView {
	top := report.TopFindings
	if reportType == htmlreport.TypeClient {
		top = []checks.Result{}
		for _, finding := range report.TopFindings {
			if !finding.HiddenInClientReport {
				top = append(top, finding)
			}
		}
	}
	if len(top) > 5 {
		top = top[:5]
	}

	return hostView{
		HostLabel:    hostName(report),
		IPLabel:      hostIP(report),
		Platform:     platformLabel(report),
		Score:        report.Score,
		IssueCount:   totalIssueCount(report.SeverityIssues),
		IssueCounts:  report.SeverityIssues,
		TopFindings:  top,
		ModuleCounts: report.ModuleSummary,
	}
}

var pageTemplate = template.Must(template.New("batch-report").Funcs(template.FuncMap{
	"upper":         strings.ToUpper,
	"count":         severityCount,
	"scoreClass":    scoreClass,
	"severityClass": severityClass,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .Title }}</title>
  <style>
    :root {
      --bg: #f8fafc;
      --ink: #111827;
      --muted: #667085;
      --line: #e5e7eb;
      --panel: #ffffff;
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #f59e0b;
      --low: #2563eb;
      --pass: #16a34a;
      --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); line-height: 1.5; }
    .page { max-width: 1160px; margin: 0 auto; padding: 40px 24px 64px; }
    .cover, .card, .host { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
    .cover { padding: 44px; min-height: 420px; display: grid; align-content: space-between; page-break-after: always; }
    .eyebrow { color: #475467; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0; }
    h1 { margin: 10px 0 0; font-size: 50px; line-height: 1.05; letter-spacing: 0; }
    h2 { margin: 34px 0 16px; font-size: 24px; letter-spacing: 0; }
    h3 { margin: 0; font-size: 18px; letter-spacing: 0; }
    p { margin: 8px 0 0; }
    .muted { color: var(--muted); }
    .score { display: inline-flex; align-items: center; justify-content: center; min-width: 96px; min-height: 48px; padding: 8px 14px; border-radius: 8px; font-weight: 800; font-size: 24px; color: #fff; background: var(--pass); }
    .score.warn { background: var(--medium); }
    .score.bad { background: var(--critical); }
    .summary { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; margin-top: 30px; }
    .card { padding: 18px; }
    .card span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .card strong { display: block; margin-top: 4px; font-size: 32px; line-height: 1; }
    .table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; box-shadow: var(--shadow); }
    .table th, .table td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }
    .table th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .hosts { display: grid; gap: 18px; }
    .host { padding: 20px; page-break-inside: avoid; }
    .host-head { display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; }
    .risk-list { display: grid; gap: 10px; margin-top: 14px; }
    .risk { border: 1px solid var(--line); border-left: 5px solid var(--low); border-radius: 8px; padding: 12px 14px; background: #fff; }
    .risk.critical { border-left-color: var(--critical); }
    .risk.high { border-left-color: var(--high); }
    .risk.medium { border-left-color: var(--medium); }
    .risk.low { border-left-color: var(--low); }
    .badges { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
    .badge { display: inline-flex; align-items: center; min-height: 24px; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--line); color: #344054; background: #fff; font-size: 12px; font-weight: 700; white-space: nowrap; }
    .badge.critical { color: var(--critical); background: #fef2f2; border-color: #fecaca; }
    .badge.high { color: var(--high); background: #fff7ed; border-color: #fed7aa; }
    .badge.medium { color: #b45309; background: #fffbeb; border-color: #fde68a; }
    .badge.low { color: var(--low); background: #eff6ff; border-color: #bfdbfe; }
    .modules { margin-top: 14px; }
    .empty { color: var(--muted); margin-top: 12px; }
    @media print {
      body { background: #fff; }
      .page { padding: 0; max-width: none; }
      .cover, .card, .host, .table { box-shadow: none; }
    }
    @media (max-width: 840px) {
      .page { padding: 24px 14px 42px; }
      .cover { padding: 24px; min-height: auto; }
      h1 { font-size: 36px; }
      .summary { grid-template-columns: 1fr 1fr; }
      .host-head { flex-direction: column; }
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="cover">
      <div>
        <div class="eyebrow">LH.pl hosting security audit · {{ upper .ReportType }} · batch</div>
        <h1>{{ .Title }}</h1>
      </div>
      <div class="summary">
        <div class="card"><span>Hosts</span><strong>{{ .HostCount }}</strong></div>
        <div class="card"><span>Average score</span><strong>{{ .AverageScore }}/100</strong></div>
        <div class="card"><span>Critical</span><strong>{{ count .IssueCounts "critical" }}</strong></div>
        <div class="card"><span>High</span><strong>{{ count .IssueCounts "high" }}</strong></div>
        <div class="card"><span>Medium</span><strong>{{ count .IssueCounts "medium" }}</strong></div>
        <div class="card"><span>Low</span><strong>{{ count .IssueCounts "low" }}</strong></div>
      </div>
    </section>

    <section>
      <h2>Host Summary</h2>
      <table class="table">
        <thead>
          <tr><th>Host</th><th>IP</th><th>Platform</th><th>Score</th><th>Issues</th></tr>
        </thead>
        <tbody>
          {{ range .Hosts }}
          <tr>
            <td>{{ .HostLabel }}</td>
            <td>{{ .IPLabel }}</td>
            <td>{{ .Platform }}</td>
            <td><span class="score {{ scoreClass .Score }}">{{ .Score }}</span></td>
            <td>{{ .IssueCount }}</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Host Sections</h2>
      <div class="hosts">
        {{ range .Hosts }}
        <article class="host">
          <div class="host-head">
            <div>
              <h3>{{ .HostLabel }}</h3>
              <p class="muted">{{ .IPLabel }} · {{ .Platform }}</p>
            </div>
            <div class="score {{ scoreClass .Score }}">{{ .Score }}/100</div>
          </div>
          <div class="badges">
            <span class="badge critical">critical {{ count .IssueCounts "critical" }}</span>
            <span class="badge high">high {{ count .IssueCounts "high" }}</span>
            <span class="badge medium">medium {{ count .IssueCounts "medium" }}</span>
            <span class="badge low">low {{ count .IssueCounts "low" }}</span>
          </div>

          <h3 style="margin-top:18px">Top risks</h3>
          {{ if .TopFindings }}
          <div class="risk-list">
            {{ range .TopFindings }}
            <div class="risk {{ severityClass .Severity }}">
              <strong>{{ .Title }}</strong>
              {{ if .ClientSummary }}<p class="muted">{{ .ClientSummary }}</p>{{ end }}
              {{ if .Recommendation }}<p><strong>Recommendation:</strong> {{ .Recommendation }}</p>{{ end }}
            </div>
            {{ end }}
          </div>
          {{ else }}<div class="empty">No fail or warning risks for this host.</div>{{ end }}

          <div class="modules">
            <h3>Module summary</h3>
            <table class="table">
              <thead><tr><th>Module</th><th>Fail</th><th>Warn</th><th>Pass</th></tr></thead>
              <tbody>
                {{ range .ModuleCounts }}
                <tr><td>{{ .ModuleID }}</td><td>{{ .Fail }}</td><td>{{ .Warn }}</td><td>{{ .Pass }}</td></tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </article>
        {{ end }}
      </div>
    </section>
  </main>
</body>
</html>
`))

func emptySeverityCounts() map[string]int {
	return map[string]int{
		string(checks.SeverityCritical): 0,
		string(checks.SeverityHigh):     0,
		string(checks.SeverityMedium):   0,
		string(checks.SeverityLow):      0,
	}
}

func totalIssueCount(counts map[string]int) int {
	return severityCount(counts, string(checks.SeverityCritical)) +
		severityCount(counts, string(checks.SeverityHigh)) +
		severityCount(counts, string(checks.SeverityMedium)) +
		severityCount(counts, string(checks.SeverityLow))
}

func severityCount(counts map[string]int, severity string) int {
	if counts == nil {
		return 0
	}
	return counts[severity]
}

func scoreClass(score int) string {
	if score >= 90 {
		return "good"
	}
	if score >= 70 {
		return "warn"
	}
	return "bad"
}

func severityClass(severity checks.Severity) string {
	switch severity {
	case checks.SeverityCritical:
		return "critical"
	case checks.SeverityHigh:
		return "high"
	case checks.SeverityMedium:
		return "medium"
	case checks.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func hostName(report audit.Report) string {
	if value := strings.TrimSpace(report.Meta["hostname"]); value != "" {
		return value
	}
	if value := strings.TrimSpace(report.Meta["host"]); value != "" {
		return value
	}
	if value := strings.TrimSpace(report.Host.Hostname); value != "" {
		return value
	}
	if value := strings.TrimSpace(report.Meta["source_file"]); value != "" {
		return strings.TrimSuffix(value, filepath.Ext(value))
	}
	return "unknown-host"
}

func hostIP(report audit.Report) string {
	if value := strings.TrimSpace(report.Meta["ip"]); value != "" {
		return value
	}
	if value := strings.TrimSpace(report.Host.PrimaryIP); value != "" {
		return value
	}
	if len(report.Host.IPAddresses) > 0 {
		return strings.Join(report.Host.IPAddresses, ", ")
	}
	return "not captured"
}

func platformLabel(report audit.Report) string {
	parts := []string{}
	if value := strings.TrimSpace(report.Host.OSRelease["PRETTY_NAME"]); value != "" {
		parts = append(parts, value)
	}
	if report.Host.GOOS != "" || report.Host.GOARCH != "" {
		parts = append(parts, strings.Trim(strings.TrimSpace(report.Host.GOOS+"/"+report.Host.GOARCH), "/"))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " · ")
}
