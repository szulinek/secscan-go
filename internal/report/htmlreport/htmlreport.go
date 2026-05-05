package htmlreport

import (
	"html/template"
	"io"
	"strings"

	"secscan/internal/audit"
	"secscan/internal/checks"
)

type Type string

const (
	TypeClient Type = "client"
	TypeAdmin  Type = "admin"
)

type viewData struct {
	Report         audit.Report
	ReportType     string
	Title          string
	GeneratedAt    string
	Score          int
	SeverityCounts map[string]int
	TopFindings    []checks.Result
	Sections       []moduleSection
	IsClient       bool
}

type moduleSection struct {
	ID       string
	Name     string
	Detected bool
	Selected bool
	Findings []checks.Result
}

func Render(w io.Writer, report audit.Report, reportType Type) error {
	audit.PrepareReport(&report)
	data := buildView(report, reportType)
	return pageTemplate.Execute(w, data)
}

func buildView(report audit.Report, reportType Type) viewData {
	findings := report.AdminFindings
	if reportType == TypeClient {
		findings = report.ClientFindings
	}

	byModule := map[string][]checks.Result{}
	for _, finding := range findings {
		byModule[finding.ModuleID] = append(byModule[finding.ModuleID], finding)
	}

	sections := make([]moduleSection, 0, len(report.Modules))
	for _, module := range report.Modules {
		sections = append(sections, moduleSection{
			ID:       module.ID,
			Name:     module.Name,
			Detected: module.Detected,
			Selected: module.Selected,
			Findings: byModule[module.ID],
		})
	}

	top := report.TopFindings
	if reportType == TypeClient {
		top = []checks.Result{}
		for _, finding := range report.TopFindings {
			if !finding.HiddenInClientReport {
				top = append(top, finding)
			}
		}
	}

	title := "Security Audit Report"
	if reportType == TypeAdmin {
		title = "Security Audit Report - Admin"
	}

	return viewData{
		Report:         report,
		ReportType:     string(reportType),
		Title:          title,
		GeneratedAt:    report.GeneratedAt,
		Score:          report.Score,
		SeverityCounts: report.SeverityCounts,
		TopFindings:    top,
		Sections:       sections,
		IsClient:       reportType == TypeClient,
	}
}

var pageTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":       strings.ToUpper,
	"statusClass": statusClass,
	"scoreClass":  scoreClass,
	"count":       severityCount,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .Title }}</title>
  <style>
    :root { color-scheme: light; --bg:#f5f7fb; --ink:#172033; --muted:#657083; --line:#dfe5ef; --panel:#fff; --accent:#2357d6; --fail:#b42318; --warn:#b45f06; --pass:#137333; --info:#3b526b; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); line-height: 1.45; }
    .page { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
    .title-page { min-height: 360px; display: grid; align-content: center; gap: 24px; border-bottom: 1px solid var(--line); margin-bottom: 28px; }
    .eyebrow { color: var(--accent); font-size: 13px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }
    h1 { font-size: 42px; line-height: 1.05; margin: 0; letter-spacing: 0; }
    h2 { font-size: 22px; margin: 32px 0 14px; }
    h3 { font-size: 17px; margin: 0; }
    .meta { color: var(--muted); display: flex; flex-wrap: wrap; gap: 12px 22px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
    .score-card { display:flex; align-items:center; gap:20px; background:var(--panel); border:1px solid var(--line); padding:22px; border-radius:8px; margin-bottom:18px; }
    .score { width:104px; height:104px; border-radius:50%; display:grid; place-items:center; font-size:34px; font-weight:800; border:10px solid var(--accent); background:#f7fbff; }
    .score.good { border-color: var(--pass); } .score.warn { border-color: var(--warn); } .score.bad { border-color: var(--fail); }
    .stat { background: var(--panel); border: 1px solid var(--line); padding: 16px; border-radius: 8px; }
    .stat strong { display:block; font-size: 28px; }
    .muted { color: var(--muted); }
    .list { display: grid; gap: 10px; }
    .finding { background: var(--panel); border: 1px solid var(--line); border-left: 5px solid var(--info); border-radius: 8px; padding: 14px 16px; }
    .finding.fail { border-left-color: var(--fail); } .finding.warn { border-left-color: var(--warn); } .finding.pass { border-left-color: var(--pass); } .finding.error { border-left-color: var(--fail); }
    .finding-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }
    .badges { display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end; }
    .badge { border:1px solid var(--line); background:#f8fafc; color:#26384d; padding:3px 8px; border-radius:999px; font-size:12px; font-weight:700; }
    .badge.fail, .badge.error { color:var(--fail); background:#fff5f4; } .badge.warn { color:var(--warn); background:#fff8ed; } .badge.pass { color:var(--pass); background:#effaf2; }
    details { margin-top: 10px; color: var(--muted); }
    details div { margin-top: 8px; white-space: pre-wrap; }
    .module { background: var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin-bottom:14px; }
    .module-title { display:flex; justify-content:space-between; gap:10px; align-items:center; margin-bottom:12px; }
    .empty { color: var(--muted); padding: 10px 0; }
    @media (max-width: 760px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } h1 { font-size: 32px; } .score-card { align-items:flex-start; flex-direction:column; } }
  </style>
</head>
<body>
  <main class="page">
    <section class="title-page">
      <div>
        <div class="eyebrow">secscan {{ .Report.Version }} · {{ upper .ReportType }}</div>
        <h1>{{ .Title }}</h1>
      </div>
      <div class="meta">
        <span>Generated: {{ .GeneratedAt }}</span>
        <span>OS: {{ .Report.Host.GOOS }}/{{ .Report.Host.GOARCH }}</span>
        {{ with index .Report.Host.OSRelease "PRETTY_NAME" }}<span>{{ . }}</span>{{ end }}
      </div>
    </section>

    <section class="score-card">
      <div class="score {{ scoreClass .Score }}">{{ .Score }}</div>
      <div>
        <h2 style="margin:0 0 6px">Security score</h2>
        <div class="muted">Score starts at 100 and is reduced by fail/warn findings according to severity.</div>
      </div>
    </section>

    <section class="grid" aria-label="Severity summary">
      <div class="stat"><span class="muted">Critical</span><strong>{{ count .SeverityCounts "critical" }}</strong></div>
      <div class="stat"><span class="muted">High</span><strong>{{ count .SeverityCounts "high" }}</strong></div>
      <div class="stat"><span class="muted">Medium</span><strong>{{ count .SeverityCounts "medium" }}</strong></div>
      <div class="stat"><span class="muted">Low</span><strong>{{ count .SeverityCounts "low" }}</strong></div>
    </section>

    <section>
      <h2>Top Risks</h2>
      {{ if .TopFindings }}
      <div class="list">
        {{ range .TopFindings }}{{ template "finding" . }}{{ end }}
      </div>
      {{ else }}<div class="empty">No fail or warning findings for this report type.</div>{{ end }}
    </section>

    <section>
      <h2>Modules</h2>
      {{ range .Sections }}
      <div class="module">
        <div class="module-title">
          <h3>{{ .Name }}</h3>
          <div class="badges"><span class="badge">detected: {{ .Detected }}</span><span class="badge">selected: {{ .Selected }}</span></div>
        </div>
        {{ if .Findings }}
        <div class="list">
          {{ range .Findings }}{{ template "finding" . }}{{ end }}
        </div>
        {{ else }}<div class="empty">No findings shown in this report.</div>{{ end }}
      </div>
      {{ end }}
    </section>
  </main>
</body>
</html>

{{ define "finding" }}
<div class="finding {{ statusClass .Status }}">
  <div class="finding-head">
    <div>
      <h3>{{ .Title }}</h3>
      <div class="muted">{{ .ClientSummary }}</div>
    </div>
    <div class="badges"><span class="badge {{ statusClass .Status }}">{{ .Status }}</span><span class="badge">{{ .Severity }}</span><span class="badge">{{ .Category }}</span></div>
  </div>
  {{ if .Impact }}<p><strong>Impact:</strong> {{ .Impact }}</p>{{ end }}
  {{ if .Recommendation }}<p><strong>Recommendation:</strong> {{ .Recommendation }}</p>{{ end }}
  <details>
    <summary>Details</summary>
    {{ if .Evidence }}<div><strong>Evidence:</strong> {{ .Evidence }}</div>{{ end }}
    {{ if .AdminDetails }}<div><strong>Admin details:</strong> {{ .AdminDetails }}</div>{{ end }}
    {{ if .Error }}<div><strong>Error:</strong> {{ .Error }}</div>{{ end }}
  </details>
</div>
{{ end }}
`))

func statusClass(status checks.Status) string {
	switch status {
	case checks.StatusFail:
		return "fail"
	case checks.StatusWarn:
		return "warn"
	case checks.StatusPass:
		return "pass"
	case checks.StatusError:
		return "error"
	default:
		return "info"
	}
}

func scoreClass(score int) string {
	if score >= 85 {
		return "good"
	}
	if score >= 65 {
		return "warn"
	}
	return "bad"
}

func severityCount(counts map[string]int, severity string) int {
	if counts == nil {
		return 0
	}
	return counts[severity]
}
