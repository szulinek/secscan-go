package runreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/execx"
	"secscan/internal/report/htmlreport"
	"secscan/internal/report/pdfreport"
	"secscan/internal/report/publishreport"
	"secscan/internal/report/smtpreport"
)

type Options struct {
	AllModules     bool
	ReportType     htmlreport.Type
	AllowAdmin     bool
	OutputDir      string
	Publish        bool
	PublishOptions publishreport.Options
	Latest         bool
	To             string
	NoEmail        bool
	PDF            bool
	KeepArtifacts  bool
	SMTPConfig     string
	WKHTMLToPDF    string
	Now            time.Time
}

type Result struct {
	AuditPath string
	HTMLPath  string
	PDFPath   string
	PublicURL string
	Report    audit.Report
}

type Dependencies struct {
	Runner      execx.Runner
	Registry    checks.Registry
	Publisher   Publisher
	LoadSMTP    func(string) (smtpreport.Config, error)
	SendMail    func(smtpreport.Config, smtpreport.Message) error
	PDFRenderer func(io.Writer, audit.Report, htmlreport.Type, pdfreport.Options) error
}

type Publisher interface {
	Publish(ctx context.Context, report audit.Report, options publishreport.Options, stdout io.Writer) (string, error)
}

type LocalPublisher struct{}

func (LocalPublisher) Publish(ctx context.Context, report audit.Report, options publishreport.Options, stdout io.Writer) (string, error) {
	return publishreport.Publish(ctx, report, options, publishreport.LocalRunner{}, stdout)
}

func Run(ctx context.Context, options Options, deps Dependencies, stdout io.Writer) (Result, error) {
	options = normalize(options)
	if err := validate(options); err != nil {
		return Result{}, err
	}
	deps = normalizeDeps(deps)

	report := audit.RunWithOptions(ctx, deps.Runner, deps.Registry, audit.Options{AllModules: options.AllModules})
	stem := artifactStem(report, options.Now)
	if err := os.MkdirAll(options.OutputDir, 0755); err != nil {
		return Result{}, fmt.Errorf("create output dir: %w", err)
	}

	result := Result{Report: report}
	result.AuditPath = filepath.Join(options.OutputDir, stem+".json")
	result.HTMLPath = filepath.Join(options.OutputDir, stem+".html")
	result.PDFPath = filepath.Join(options.OutputDir, stem+".pdf")

	if err := writeAuditJSON(result.AuditPath, report); err != nil {
		return Result{}, err
	}
	if err := writeHTML(result.HTMLPath, report, options.ReportType); err != nil {
		return Result{}, err
	}
	if options.PDF {
		if err := writePDF(result.PDFPath, report, options, deps); err != nil {
			return Result{}, err
		}
	} else {
		result.PDFPath = ""
	}

	if options.Publish {
		publishOptions := options.PublishOptions
		publishOptions.Input = result.AuditPath
		publishOptions.ReportType = options.ReportType
		publishOptions.AllowAdmin = options.AllowAdmin
		publishOptions.Latest = options.Latest
		url, err := deps.Publisher.Publish(ctx, report, publishOptions, stdout)
		if err != nil {
			return Result{}, fmt.Errorf("publish report: %w", err)
		}
		result.PublicURL = url
	}

	recipients := smtpreport.ParseRecipients(options.To)
	if len(recipients) > 0 && !options.NoEmail {
		if result.PublicURL == "" && !options.PDF {
			return Result{}, errors.New("email requires --publish or --pdf")
		}
		if err := sendEmail(result, recipients, options, deps); err != nil {
			return Result{}, err
		}
	}

	if !options.KeepArtifacts {
		removeArtifact(result.AuditPath)
		removeArtifact(result.HTMLPath)
		removeArtifact(result.PDFPath)
	}

	return result, nil
}

func normalize(options Options) Options {
	if options.ReportType == "" {
		options.ReportType = htmlreport.TypeClient
	}
	if options.OutputDir == "" {
		options.OutputDir = "reports"
	}
	if options.SMTPConfig == "" {
		options.SMTPConfig = "config/smtp.json"
	}
	if options.WKHTMLToPDF == "" {
		options.WKHTMLToPDF = "wkhtmltopdf"
	}
	return options
}

func validate(options Options) error {
	if options.ReportType != htmlreport.TypeClient && options.ReportType != htmlreport.TypeAdmin {
		return fmt.Errorf("unsupported report type: %s", options.ReportType)
	}
	if options.ReportType == htmlreport.TypeAdmin && !options.AllowAdmin {
		return errors.New("admin run requires --allow-admin")
	}
	if options.Publish {
		publishOptions := options.PublishOptions
		publishOptions.Input = "audit.json"
		publishOptions.ReportType = options.ReportType
		publishOptions.AllowAdmin = options.AllowAdmin
		if err := publishreport.Validate(publishOptions); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDeps(deps Dependencies) Dependencies {
	if deps.Runner == nil {
		deps.Runner = execx.LocalRunner{}
	}
	if deps.Publisher == nil {
		deps.Publisher = LocalPublisher{}
	}
	if deps.LoadSMTP == nil {
		deps.LoadSMTP = smtpreport.LoadConfig
	}
	if deps.SendMail == nil {
		deps.SendMail = smtpreport.Send
	}
	if deps.PDFRenderer == nil {
		deps.PDFRenderer = pdfreport.Render
	}
	return deps
}

func writeAuditJSON(path string, report audit.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create audit json: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write audit json: %w", err)
	}
	return nil
}

func writeHTML(path string, report audit.Report, reportType htmlreport.Type) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create html report: %w", err)
	}
	defer file.Close()

	if err := htmlreport.Render(file, report, reportType); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}

func writePDF(path string, report audit.Report, options Options, deps Dependencies) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pdf report: %w", err)
	}
	defer file.Close()

	if err := deps.PDFRenderer(file, report, options.ReportType, pdfreport.Options{Binary: options.WKHTMLToPDF}); err != nil {
		return fmt.Errorf("render pdf report: %w", err)
	}
	return nil
}

func sendEmail(result Result, recipients []string, options Options, deps Dependencies) error {
	config, err := deps.LoadSMTP(options.SMTPConfig)
	if err != nil {
		return fmt.Errorf("read smtp config: %w", err)
	}
	body := "Dzien dobry,\n\nRaport bezpieczenstwa zostal wygenerowany."
	if result.PublicURL != "" {
		body += "\n\nLink do raportu: " + result.PublicURL
	}
	body += "\n"

	message := smtpreport.Message{
		To:      recipients,
		Subject: "Security Audit Report",
		Body:    body,
	}
	if options.PDF {
		data, err := os.ReadFile(result.PDFPath)
		if err != nil {
			return fmt.Errorf("read pdf attachment: %w", err)
		}
		message.Attachment = data
		message.AttachmentName = filepath.Base(result.PDFPath)
	}
	if err := deps.SendMail(config, message); err != nil {
		return fmt.Errorf("send report email: %w", err)
	}
	return nil
}

func artifactStem(report audit.Report, now time.Time) string {
	if now.IsZero() {
		now = time.Now()
	}
	host := report.Host.Hostname
	if strings.TrimSpace(host) == "" && len(report.Host.IPAddresses) > 0 {
		host = report.Host.IPAddresses[0]
	}
	if strings.TrimSpace(host) == "" {
		host = "host"
	}
	return publishreport.SanitizeFilenamePart(host) + "-" + now.Format("2006-01-02-1504")
}

func removeArtifact(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func RenderPDFBytes(report audit.Report, reportType htmlreport.Type, options pdfreport.Options) ([]byte, error) {
	var out bytes.Buffer
	if err := pdfreport.Render(&out, report, reportType, options); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
