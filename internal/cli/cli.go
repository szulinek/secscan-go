package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"secscan/internal/audit"
	"secscan/internal/execx"
	"secscan/internal/report/batchreport"
	"secscan/internal/report/htmlreport"
	"secscan/internal/report/pdfreport"
	"secscan/internal/report/publishreport"
	"secscan/internal/report/runreport"
	"secscan/internal/report/smtpreport"
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	command := args[0]
	switch command {
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "detect":
		return runDetect(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "batch-report":
		return runBatchReport(args[1:], stdout, stderr)
	case "send-report":
		return runSendReport(args[1:], stdout, stderr)
	case "publish-report":
		return runPublishReport(args[1:], stdout, stderr)
	case "run":
		return runEndToEnd(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "%s %s\n", audit.ToolName, audit.Version)
		return 0
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", command)
		printUsage(stderr)
		return 2
	}
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "command timeout")
	format := flags.String("format", "json", "output format: json")
	allModules := false
	flags.BoolVar(&allModules, "all", false, "run all registered modules, even when a service was not detected")
	flags.BoolVar(&allModules, "all-modules", false, "run all registered modules, even when a service was not detected")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "json" {
		fmt.Fprintf(stderr, "unsupported audit format: %s\n", *format)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := audit.RunWithOptions(ctx, execx.LocalRunner{}, audit.DefaultRegistry(), audit.Options{
		AllModules: allModules,
	})

	return writeJSON(stdout, report)
}

func runDetect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("detect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "command timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := audit.Detect(ctx, execx.LocalRunner{}, audit.DefaultRegistry())
	return writeJSON(stdout, report)
}

func runReport(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input audit JSON file")
	format := flags.String("format", "html", "report format: html or pdf")
	reportType := flags.String("type", "client", "report type: client or admin")
	wkhtmltopdf := flags.String("wkhtmltopdf", "wkhtmltopdf", "path to wkhtmltopdf binary for PDF output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *input == "" {
		fmt.Fprintln(stderr, "missing required --input audit.json")
		return 2
	}
	if *format != "html" && *format != "pdf" {
		fmt.Fprintf(stderr, "unsupported report format: %s\n", *format)
		return 2
	}
	if *reportType != string(htmlreport.TypeClient) && *reportType != string(htmlreport.TypeAdmin) {
		fmt.Fprintf(stderr, "unsupported report type: %s\n", *reportType)
		return 2
	}

	report, err := readAuditReport(*input)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	switch *format {
	case "html":
		if err := htmlreport.Render(stdout, report, htmlreport.Type(*reportType)); err != nil {
			fmt.Fprintf(stderr, "render report: %v\n", err)
			return 1
		}
	case "pdf":
		if err := pdfreport.Render(stdout, report, htmlreport.Type(*reportType), pdfreport.Options{Binary: *wkhtmltopdf}); err != nil {
			fmt.Fprintf(stderr, "render pdf: %v\n", err)
			return 1
		}
	}

	return 0
}

func runSendReport(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("send-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input audit JSON file")
	reportType := flags.String("type", "client", "report type: client or admin")
	smtpConfig := flags.String("smtp-config", "config/smtp.json", "SMTP config JSON file")
	to := flags.String("to", "", "recipient email address; comma separated values are allowed")
	subject := flags.String("subject", "Security Audit Report", "email subject")
	body := flags.String("body", "W załączniku przesyłam raport bezpieczeństwa serwera.", "plain-text email body")
	attachment := flags.String("attachment", "security-audit-report.pdf", "PDF attachment filename")
	wkhtmltopdf := flags.String("wkhtmltopdf", "wkhtmltopdf", "path to wkhtmltopdf binary")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *input == "" {
		fmt.Fprintln(stderr, "missing required --input audit.json")
		return 2
	}
	if *reportType != string(htmlreport.TypeClient) && *reportType != string(htmlreport.TypeAdmin) {
		fmt.Fprintf(stderr, "unsupported report type: %s\n", *reportType)
		return 2
	}

	report, err := readAuditReport(*input)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var pdf bytes.Buffer
	if err := pdfreport.Render(&pdf, report, htmlreport.Type(*reportType), pdfreport.Options{Binary: *wkhtmltopdf}); err != nil {
		fmt.Fprintf(stderr, "render pdf: %v\n", err)
		return 1
	}

	config, err := smtpreport.LoadConfig(*smtpConfig)
	if err != nil {
		fmt.Fprintf(stderr, "read smtp config: %v\n", err)
		return 1
	}

	recipients := smtpreport.ParseRecipients(*to)
	if len(recipients) == 0 {
		recipients = config.DefaultTo
	}

	message := smtpreport.Message{
		To:             recipients,
		Subject:        *subject,
		Body:           *body,
		AttachmentName: *attachment,
		Attachment:     pdf.Bytes(),
	}
	if err := smtpreport.Send(config, message); err != nil {
		fmt.Fprintf(stderr, "send report: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "sent %s PDF report to %s\n", *reportType, strings.Join(recipients, ", "))
	return 0
}

func runPublishReport(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("publish-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input audit JSON file")
	reportType := flags.String("type", string(htmlreport.TypeClient), "report type: client or admin")
	allowAdmin := flags.Bool("allow-admin", false, "allow publishing admin report")
	sshHost := flags.String("ssh-host", "", "SSH host for rsync upload")
	sshUser := flags.String("ssh-user", "", "SSH user for rsync upload")
	sshPort := flags.Int("ssh-port", 22, "SSH port for rsync upload")
	remoteDir := flags.String("remote-dir", "", "remote directory for report upload")
	publicBaseURL := flags.String("public-base-url", "", "public base URL for uploaded reports")
	latest := flags.Bool("latest", false, "also upload the report as latest.html")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	options := publishreport.Options{
		Input:         *input,
		ReportType:    htmlreport.Type(*reportType),
		AllowAdmin:    *allowAdmin,
		SSHHost:       *sshHost,
		SSHUser:       *sshUser,
		SSHPort:       *sshPort,
		RemoteDir:     *remoteDir,
		PublicBaseURL: *publicBaseURL,
		Latest:        *latest,
	}
	if err := publishreport.Validate(options); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	report, err := readAuditReport(*input)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if _, err := publishreport.Publish(context.Background(), report, options, publishreport.LocalRunner{}, stdout); err != nil {
		fmt.Fprintf(stderr, "publish report: %v\n", err)
		return 1
	}
	return 0
}

func runEndToEnd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "command timeout")
	allModules := false
	flags.BoolVar(&allModules, "all", false, "run all registered modules")
	flags.BoolVar(&allModules, "all-modules", false, "run all registered modules")
	reportType := flags.String("type", string(htmlreport.TypeClient), "report type: client or admin")
	allowAdmin := flags.Bool("allow-admin", false, "allow admin report")
	outputDir := flags.String("output-dir", "reports", "directory for generated artifacts")
	publish := flags.Bool("publish", false, "publish HTML report through rsync/SSH")
	sshHost := flags.String("ssh-host", "", "SSH host for rsync upload")
	sshUser := flags.String("ssh-user", "", "SSH user for rsync upload")
	sshPort := flags.Int("ssh-port", 22, "SSH port for rsync upload")
	remoteDir := flags.String("remote-dir", "", "remote directory for report upload")
	publicBaseURL := flags.String("public-base-url", "", "public base URL for uploaded reports")
	latest := flags.Bool("latest", false, "also upload latest.html when publishing")
	smtpConfig := flags.String("smtp-config", "config/smtp.json", "SMTP config JSON file")
	to := flags.String("to", "", "recipient email address; comma separated values are allowed")
	noEmail := flags.Bool("no-email", false, "do not send email even when --to is provided")
	pdf := flags.Bool("pdf", false, "also render PDF artifact")
	keepArtifacts := flags.Bool("keep-artifacts", true, "keep generated local artifacts")
	wkhtmltopdf := flags.String("wkhtmltopdf", "wkhtmltopdf", "path to wkhtmltopdf binary")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	options := runreport.Options{
		AllModules:    allModules,
		ReportType:    htmlreport.Type(*reportType),
		AllowAdmin:    *allowAdmin,
		OutputDir:     *outputDir,
		Publish:       *publish,
		Latest:        *latest,
		To:            *to,
		NoEmail:       *noEmail,
		PDF:           *pdf,
		KeepArtifacts: *keepArtifacts,
		SMTPConfig:    *smtpConfig,
		WKHTMLToPDF:   *wkhtmltopdf,
		PublishOptions: publishreport.Options{
			SSHHost:       *sshHost,
			SSHUser:       *sshUser,
			SSHPort:       *sshPort,
			RemoteDir:     *remoteDir,
			PublicBaseURL: *publicBaseURL,
		},
	}
	result, err := runreport.Run(ctx, options, runreport.Dependencies{
		Runner:   execx.LocalRunner{},
		Registry: audit.DefaultRegistry(),
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "run: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "wrote audit JSON: %s\n", result.AuditPath)
	fmt.Fprintf(stdout, "wrote HTML report: %s\n", result.HTMLPath)
	if result.PDFPath != "" {
		fmt.Fprintf(stdout, "wrote PDF report: %s\n", result.PDFPath)
	}
	if result.PublicURL != "" {
		fmt.Fprintf(stdout, "published report: %s\n", result.PublicURL)
	}
	return 0
}

func runBatchReport(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("batch-report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputDir := flags.String("input-dir", "", "directory with JSON audit reports")
	format := flags.String("format", "html", "batch report format: html or pdf")
	reportType := flags.String("type", "client", "report type: client or admin")
	output := flags.String("output", "", "output file path")
	wkhtmltopdf := flags.String("wkhtmltopdf", "wkhtmltopdf", "path to wkhtmltopdf binary for PDF output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *inputDir == "" {
		fmt.Fprintln(stderr, "missing required --input-dir reports")
		return 2
	}
	if *output == "" {
		fmt.Fprintln(stderr, "missing required --output file")
		return 2
	}
	if *format != "html" && *format != "pdf" {
		fmt.Fprintf(stderr, "unsupported batch report format: %s\n", *format)
		return 2
	}
	if *reportType != string(htmlreport.TypeClient) && *reportType != string(htmlreport.TypeAdmin) {
		fmt.Fprintf(stderr, "unsupported report type: %s\n", *reportType)
		return 2
	}

	reports, err := batchreport.LoadReports(*inputDir)
	if err != nil {
		fmt.Fprintf(stderr, "load batch reports: %v\n", err)
		return 1
	}

	file, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(stderr, "create output: %v\n", err)
		return 1
	}
	defer file.Close()

	switch *format {
	case "html":
		if err := batchreport.Render(file, reports, htmlreport.Type(*reportType)); err != nil {
			fmt.Fprintf(stderr, "render batch report: %v\n", err)
			return 1
		}
	case "pdf":
		var html bytes.Buffer
		if err := batchreport.Render(&html, reports, htmlreport.Type(*reportType)); err != nil {
			fmt.Fprintf(stderr, "render batch report: %v\n", err)
			return 1
		}
		if err := pdfreport.RenderHTML(file, html.Bytes(), pdfreport.Options{Binary: *wkhtmltopdf}); err != nil {
			fmt.Fprintf(stderr, "render batch pdf: %v\n", err)
			return 1
		}
	}

	fmt.Fprintf(stdout, "wrote %s batch report for %d host(s) to %s\n", *format, len(reports), *output)
	return 0
}

func readAuditReport(path string) (audit.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return audit.Report{}, fmt.Errorf("read input: %w", err)
	}

	var report audit.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return audit.Report{}, fmt.Errorf("parse input JSON: %w", err)
	}

	return report, nil
}

func writeJSON(stdout io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 1
	}

	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`
secscan - local security audit MVP

Usage:
  secscan audit [--all] [--format json] [--timeout 30s]
  secscan detect [--timeout 30s]
  secscan report --input audit.json --format html --type client
  secscan report --input audit.json --format pdf --type client > report.pdf
  secscan batch-report --input-dir reports --format pdf --type client --output client-audit.pdf
  secscan send-report --input audit.json --type client --smtp-config config/smtp.json --to client@example.com
  secscan publish-report --input audit.json --ssh-host reports.example.pl --ssh-user lh --ssh-port 40022 --remote-dir /home/lh/domains/example.pl/public_html/audits --public-base-url https://example.pl/audits
  secscan run --all --type client --output-dir reports --publish --ssh-host reports.example.pl --ssh-user lh --ssh-port 40022 --remote-dir /home/lh/domains/example.pl/public_html/audits --public-base-url https://example.pl/audits --latest --smtp-config config/smtp.json --to client@example.com
  secscan report --input audit.json --format html --type admin
  secscan version

Commands:
  audit    detect host/services, run matching checks, print JSON
  detect   detect host/services/modules only, print JSON
  report   render a JSON audit into a client or admin HTML/PDF report
  batch-report render many JSON audits into one client or admin HTML/PDF report
  send-report render a client/admin PDF report and send it through SMTP
  publish-report render a client HTML report and upload it through rsync/SSH
  run      run audit, save artifacts, optionally publish and email
  version  print secscan version

Audit flags:
  --all, --all-modules  run every registered module; useful for Ansible batch audits
`))
}
