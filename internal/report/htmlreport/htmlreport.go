package htmlreport

import (
	"html/template"
	"io"
	"strings"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/system"
)

type Type string

const (
	TypeClient Type = "client"
	TypeAdmin  Type = "admin"
)

type viewData struct {
	Report          audit.Report
	ReportType      string
	Title           string
	GeneratedAt     string
	Score           int
	HostLabel       string
	PlatformLabel   string
	ExecutiveText   string
	IssueCounts     map[string]int
	TopFindings     []checks.Result
	TopEmptyText    string
	Sections        []moduleSection
	ShowInventory   bool
	Inventory       audit.Inventory
	CollectionNotes []string
}

type moduleSection struct {
	ID              string
	Name            string
	Detected        bool
	Selected        bool
	Summary         audit.ModuleSummary
	VisibleFindings []checks.Result
	PassingFindings []checks.Result
}

func Render(w io.Writer, report audit.Report, reportType Type) error {
	audit.PrepareReport(&report)
	data := buildView(report, reportType)
	return pageTemplate.Execute(w, data)
}

func buildView(report audit.Report, reportType Type) viewData {
	findings := adminReportFindings(report)
	if reportType == TypeClient {
		findings = report.ClientFindings
	}

	byModule := map[string][]checks.Result{}
	for _, finding := range findings {
		byModule[finding.ModuleID] = append(byModule[finding.ModuleID], finding)
	}

	moduleByID := map[string]audit.ModuleReport{}
	for _, module := range report.Modules {
		moduleByID[module.ID] = module
	}

	sections := make([]moduleSection, 0, len(report.ModuleSummary))
	seen := map[string]struct{}{}
	for _, summary := range report.ModuleSummary {
		if summary.ModuleID == "" {
			continue
		}
		sections = append(sections, buildModuleSection(summary, moduleByID[summary.ModuleID], byModule[summary.ModuleID]))
		seen[summary.ModuleID] = struct{}{}
	}
	for _, module := range report.Modules {
		if _, ok := seen[module.ID]; ok {
			continue
		}
		sections = append(sections, buildModuleSection(audit.ModuleSummary{ModuleID: module.ID}, module, byModule[module.ID]))
	}

	top := report.TopFindings
	if reportType == TypeClient {
		top = []checks.Result{}
		for _, finding := range report.TopFindings {
			if finding.HiddenInClientReport {
				continue
			}
			top = append(top, finding)
		}
	}
	if len(top) > 10 {
		top = top[:10]
	}

	title := "Security Audit Report"
	if reportType == TypeAdmin {
		title = "Security Audit Report - Admin"
	}

	return viewData{
		Report:          report,
		ReportType:      string(reportType),
		Title:           title,
		GeneratedAt:     report.GeneratedAt,
		Score:           report.Score,
		HostLabel:       hostLabel(report),
		PlatformLabel:   platformLabel(report.Host),
		ExecutiveText:   executiveText(report.Score, report.SeverityIssues),
		IssueCounts:     report.SeverityIssues,
		TopFindings:     top,
		TopEmptyText:    topEmptyText(reportType),
		Sections:        sections,
		ShowInventory:   reportType == TypeAdmin,
		Inventory:       report.Inventory,
		CollectionNotes: report.Errors,
	}
}

func buildModuleSection(summary audit.ModuleSummary, module audit.ModuleReport, findings []checks.Result) moduleSection {
	name := module.Name
	if name == "" {
		name = summary.ModuleID
	}

	section := moduleSection{
		ID:       summary.ModuleID,
		Name:     name,
		Detected: module.Detected,
		Selected: module.Selected,
		Summary:  summary,
	}

	for _, finding := range findings {
		switch finding.Status {
		case checks.StatusFail, checks.StatusWarn, checks.StatusError:
			section.VisibleFindings = append(section.VisibleFindings, finding)
		case checks.StatusPass:
			section.PassingFindings = append(section.PassingFindings, finding)
		}
	}

	return section
}

func adminReportFindings(report audit.Report) []checks.Result {
	findings := []checks.Result{}
	for _, result := range report.Results {
		switch result.Status {
		case checks.StatusFail, checks.StatusWarn, checks.StatusError, checks.StatusPass:
			findings = append(findings, result)
		}
	}
	return findings
}

var pageTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":         strings.ToUpper,
	"statusClass":   statusClass,
	"severityClass": severityClass,
	"scoreClass":    scoreClass,
	"scoreLabel":    scoreLabel,
	"count":         severityCount,
	"detectedLabel": detectedLabel,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .Title }}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --ink: #111827;
      --muted: #667085;
      --line: #e5e7eb;
      --panel: #ffffff;
      --soft: #f3f4f6;
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #f59e0b;
      --low: #2563eb;
      --pass: #16a34a;
      --warn: #f59e0b;
      --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
      line-height: 1.5;
    }
    .page { max-width: 1120px; margin: 0 auto; padding: 40px 24px 64px; }
    .cover {
      min-height: 520px;
      display: grid;
      align-content: space-between;
      gap: 44px;
      padding: 44px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      page-break-after: always;
    }
    .cover-top { display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; }
    .eyebrow {
      color: #475467;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      font-weight: 700;
      margin-bottom: 14px;
    }
    h1 { font-size: 52px; line-height: 1.02; margin: 0; letter-spacing: 0; }
    h2 { font-size: 24px; margin: 34px 0 16px; letter-spacing: 0; }
    h3 { font-size: 17px; margin: 0; letter-spacing: 0; }
    p { margin: 10px 0 0; }
    .muted { color: var(--muted); }
    .meta-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-top: 34px; }
    .meta-item { padding: 14px 16px; background: var(--soft); border-radius: 8px; border: 1px solid var(--line); }
    .meta-item span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .meta-item strong { display: block; margin-top: 3px; font-size: 15px; overflow-wrap: anywhere; }
    .score-panel { display: flex; align-items: center; gap: 20px; justify-content: flex-end; }
    .score {
      width: 148px;
      height: 148px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: #fff;
      border: 12px solid var(--pass);
      font-size: 38px;
      font-weight: 800;
      box-shadow: inset 0 0 0 1px rgba(17, 24, 39, 0.06);
    }
    .score.good { border-color: var(--pass); }
    .score.warn { border-color: var(--warn); }
    .score.bad { border-color: var(--critical); }
    .score-copy strong { display: block; font-size: 20px; }
    .section { margin-top: 34px; }
    .summary {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) repeat(4, minmax(112px, 1fr));
      gap: 14px;
      align-items: stretch;
    }
    .summary-copy, .stat, .risk-card, .module, .inventory-card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .summary-copy { padding: 20px; }
    .summary-copy p { font-size: 17px; margin: 0; }
    .stat { padding: 16px; border-top: 4px solid var(--low); }
    .stat.critical { border-top-color: var(--critical); }
    .stat.high { border-top-color: var(--high); }
    .stat.medium { border-top-color: var(--medium); }
    .stat.low { border-top-color: var(--low); }
    .stat span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .stat strong { display: block; margin-top: 4px; font-size: 34px; line-height: 1; }
    .risk-list { display: grid; gap: 14px; }
    .risk-card { padding: 18px; border-left: 5px solid var(--low); page-break-inside: avoid; }
    .risk-card.sev-critical { border-left-color: var(--critical); }
    .risk-card.sev-high { border-left-color: var(--high); }
    .risk-card.sev-medium { border-left-color: var(--medium); }
    .risk-card.sev-low { border-left-color: var(--low); }
    .risk-head, .module-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
    .risk-body { margin-top: 8px; max-width: 820px; }
    .recommendation { margin-top: 12px; padding: 12px 14px; background: #f8fafc; border: 1px solid var(--line); border-radius: 8px; }
    .badges { display: flex; gap: 7px; flex-wrap: wrap; justify-content: flex-end; align-items: center; }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 9px;
      border-radius: 999px;
      border: 1px solid var(--line);
      color: #344054;
      background: #fff;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }
    .badge.critical { color: var(--critical); background: #fef2f2; border-color: #fecaca; }
    .badge.high { color: var(--high); background: #fff7ed; border-color: #fed7aa; }
    .badge.medium, .badge.warn { color: #b45309; background: #fffbeb; border-color: #fde68a; }
    .badge.low { color: var(--low); background: #eff6ff; border-color: #bfdbfe; }
    .badge.pass { color: var(--pass); background: #f0fdf4; border-color: #bbf7d0; }
    .badge.fail, .badge.error { color: var(--critical); background: #fef2f2; border-color: #fecaca; }
    .modules { display: grid; gap: 16px; }
    .module { padding: 18px; page-break-inside: avoid; }
    .module-id { margin-top: 2px; font-size: 13px; color: var(--muted); }
    .module-findings { display: grid; gap: 12px; margin-top: 14px; }
    details {
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 10px 12px;
    }
    details summary { cursor: pointer; color: #344054; font-weight: 700; }
    details .detail-grid { display: grid; gap: 10px; margin-top: 10px; color: #344054; }
    .detail-grid div { white-space: pre-wrap; overflow-wrap: anywhere; }
    .empty { color: var(--muted); padding: 12px 0 0; }
    .inventory-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }
    .inventory-card { padding: 18px; }
    .table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    .table th, .table td { padding: 8px 6px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    .table th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .notes { margin-top: 12px; padding-left: 18px; color: #344054; }
    @media print {
      body { background: #fff; }
      .page { padding: 0; max-width: none; }
      .cover, .summary-copy, .stat, .risk-card, .module, .inventory-card { box-shadow: none; }
      details { break-inside: avoid; }
    }
    @media (max-width: 820px) {
      .page { padding: 24px 14px 42px; }
      .cover { padding: 24px; min-height: auto; }
      .cover-top, .score-panel, .risk-head, .module-head { flex-direction: column; align-items: flex-start; }
      h1 { font-size: 38px; }
      .meta-grid, .summary, .inventory-grid { grid-template-columns: 1fr; }
      .score { width: 124px; height: 124px; font-size: 32px; }
      .badges { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="cover">
      <div class="cover-top">
        <div>
          <div class="eyebrow">LH.pl hosting security audit · {{ upper .ReportType }}</div>
          <h1>{{ .Title }}</h1>
        </div>
        <div class="score-panel">
          <div class="score {{ scoreClass .Score }}">{{ .Score }}/100</div>
          <div class="score-copy">
            <strong>{{ scoreLabel .Score }}</strong>
            <span class="muted">Security score</span>
          </div>
        </div>
      </div>
      <div>
        <div class="meta-grid">
          <div class="meta-item"><span>Hostname / IP</span><strong>{{ .HostLabel }}</strong></div>
          <div class="meta-item"><span>Generated</span><strong>{{ .GeneratedAt }}</strong></div>
          <div class="meta-item"><span>Platform</span><strong>{{ .PlatformLabel }}</strong></div>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Executive Summary</h2>
      <div class="summary">
        <div class="summary-copy"><p>{{ .ExecutiveText }}</p></div>
        <div class="stat critical"><span>Critical</span><strong>{{ count .IssueCounts "critical" }}</strong></div>
        <div class="stat high"><span>High</span><strong>{{ count .IssueCounts "high" }}</strong></div>
        <div class="stat medium"><span>Medium</span><strong>{{ count .IssueCounts "medium" }}</strong></div>
        <div class="stat low"><span>Low</span><strong>{{ count .IssueCounts "low" }}</strong></div>
      </div>
    </section>

    <section class="section">
      <h2>Top Risks</h2>
      {{ if .TopFindings }}
      <div class="risk-list">
        {{ range .TopFindings }}{{ template "finding" . }}{{ end }}
      </div>
      {{ else }}<div class="empty">{{ .TopEmptyText }}</div>{{ end }}
    </section>

    <section class="section">
      <h2>Modules</h2>
      <div class="modules">
        {{ range .Sections }}
        <article class="module">
          <div class="module-head">
            <div>
              <h3>{{ .Name }}</h3>
              <div class="module-id">{{ .ID }} · {{ detectedLabel .Detected }}</div>
            </div>
            <div class="badges">
              <span class="badge fail">fail {{ .Summary.Fail }}</span>
              <span class="badge warn">warn {{ .Summary.Warn }}</span>
              <span class="badge pass">pass {{ .Summary.Pass }}</span>
            </div>
          </div>

          {{ if .VisibleFindings }}
          <div class="module-findings">
            {{ range .VisibleFindings }}{{ template "finding" . }}{{ end }}
          </div>
          {{ else }}<div class="empty">No fail or warning findings in this module.</div>{{ end }}

          {{ if .PassingFindings }}
          <details>
            <summary>Passing checks ({{ len .PassingFindings }})</summary>
            <div class="module-findings">
              {{ range .PassingFindings }}{{ template "finding" . }}{{ end }}
            </div>
          </details>
          {{ end }}
        </article>
        {{ end }}
      </div>
    </section>

    {{ if .ShowInventory }}
    <section class="section">
      <h2>Admin Inventory</h2>
      <div class="inventory-grid">
        <div class="inventory-card">
          <h3>Running services</h3>
          {{ if .Inventory.Services }}
          <table class="table">
            <thead><tr><th>Unit</th><th>Status</th><th>Description</th></tr></thead>
            <tbody>
              {{ range .Inventory.Services }}
              <tr><td>{{ .Unit }}</td><td>{{ .Active }}/{{ .Sub }}</td><td>{{ .Description }}</td></tr>
              {{ end }}
            </tbody>
          </table>
          {{ else }}<div class="empty">No running services were captured.</div>{{ end }}
        </div>
        <div class="inventory-card">
          <h3>Detected modules</h3>
          {{ if .Inventory.Modules }}
          <table class="table">
            <thead><tr><th>Module</th><th>Detected</th><th>Selected</th></tr></thead>
            <tbody>
              {{ range .Inventory.Modules }}
              <tr><td>{{ .Name }}<br><span class="muted">{{ .ID }}</span></td><td>{{ .Detected }}</td><td>{{ .Selected }}</td></tr>
              {{ end }}
            </tbody>
          </table>
          {{ else }}<div class="empty">No module inventory was captured.</div>{{ end }}
        </div>
      </div>
      {{ if .CollectionNotes }}
      <div class="inventory-card" style="margin-top:16px">
        <h3>Collection notes</h3>
        <ul class="notes">
          {{ range .CollectionNotes }}<li>{{ . }}</li>{{ end }}
        </ul>
      </div>
      {{ end }}
    </section>
    {{ end }}
  </main>
</body>
</html>

{{ define "finding" }}
<article class="risk-card sev-{{ severityClass .Severity }}">
  <div class="risk-head">
    <div>
      <h3>{{ .Title }}</h3>
      {{ if .ClientSummary }}<p class="risk-body muted">{{ .ClientSummary }}</p>{{ end }}
    </div>
    <div class="badges">
      <span class="badge {{ severityClass .Severity }}">{{ .Severity }}</span>
      <span class="badge {{ statusClass .Status }}">{{ .Status }}</span>
    </div>
  </div>
  {{ if .Recommendation }}<div class="recommendation"><strong>Recommendation:</strong> {{ .Recommendation }}</div>{{ end }}
  <details>
    <summary>Technical details</summary>
    <div class="detail-grid">
      {{ if .Impact }}<div><strong>Impact:</strong> {{ .Impact }}</div>{{ end }}
      {{ if .Evidence }}<div><strong>Evidence:</strong> {{ .Evidence }}</div>{{ end }}
      {{ if .AdminDetails }}<div><strong>Admin details:</strong> {{ .AdminDetails }}</div>{{ end }}
      {{ if .Error }}<div><strong>Error:</strong> {{ .Error }}</div>{{ end }}
    </div>
  </details>
</article>
{{ end }}
`))

func hostLabel(report audit.Report) string {
	if hostname := strings.TrimSpace(report.Meta["hostname"]); hostname != "" {
		return hostname
	}
	if ip := strings.TrimSpace(report.Meta["ip"]); ip != "" {
		return ip
	}
	if host := strings.TrimSpace(report.Meta["host"]); host != "" {
		return host
	}
	if hostname := strings.TrimSpace(report.Host.Hostname); hostname != "" {
		if len(report.Host.IPAddresses) > 0 {
			return hostname + " / " + report.Host.IPAddresses[0]
		}
		return hostname
	}
	if len(report.Host.IPAddresses) > 0 {
		return report.Host.IPAddresses[0]
	}
	return "Not provided in audit JSON"
}

func platformLabel(info system.Info) string {
	parts := []string{}
	if pretty := strings.TrimSpace(info.OSRelease["PRETTY_NAME"]); pretty != "" {
		parts = append(parts, pretty)
	}
	if info.GOOS != "" || info.GOARCH != "" {
		parts = append(parts, strings.Trim(strings.TrimSpace(info.GOOS+"/"+info.GOARCH), "/"))
	}
	if len(parts) == 0 {
		return "Unknown"
	}
	return strings.Join(parts, " · ")
}

func executiveText(score int, issues map[string]int) string {
	total := severityCount(issues, string(checks.SeverityCritical)) +
		severityCount(issues, string(checks.SeverityHigh)) +
		severityCount(issues, string(checks.SeverityMedium)) +
		severityCount(issues, string(checks.SeverityLow))

	if total == 0 {
		return "The system is generally secure based on the current checks. No client-visible risks were identified in this audit."
	}
	if score >= 90 {
		return "The system is generally secure, but several improvements are recommended to reduce operational and security risk."
	}
	if score >= 70 {
		return "The system has a usable security baseline, but the listed findings should be remediated to reduce exposure."
	}
	return "The system requires security attention. Prioritize critical and high findings before expanding the scope of the audit."
}

func topEmptyText(reportType Type) string {
	if reportType == TypeClient {
		return "No client-visible fail or warning findings were identified."
	}
	return "No fail or warning risks were identified."
}

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

func scoreClass(score int) string {
	if score >= 90 {
		return "good"
	}
	if score >= 70 {
		return "warn"
	}
	return "bad"
}

func scoreLabel(score int) string {
	if score >= 90 {
		return "Strong posture"
	}
	if score >= 70 {
		return "Needs improvements"
	}
	return "Action required"
}

func severityCount(counts map[string]int, severity string) int {
	if counts == nil {
		return 0
	}
	return counts[severity]
}

func detectedLabel(detected bool) string {
	if detected {
		return "detected"
	}
	return "not detected"
}
