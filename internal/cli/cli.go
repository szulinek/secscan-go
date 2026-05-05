package cli

import (
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
	"secscan/internal/report/htmlreport"
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
	format := flags.String("format", "html", "report format: html")
	reportType := flags.String("type", "client", "report type: client or admin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *input == "" {
		fmt.Fprintln(stderr, "missing required --input audit.json")
		return 2
	}
	if *format != "html" {
		fmt.Fprintf(stderr, "unsupported report format: %s\n", *format)
		return 2
	}
	if *reportType != string(htmlreport.TypeClient) && *reportType != string(htmlreport.TypeAdmin) {
		fmt.Fprintf(stderr, "unsupported report type: %s\n", *reportType)
		return 2
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}

	var report audit.Report
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(stderr, "parse input JSON: %v\n", err)
		return 1
	}

	if err := htmlreport.Render(stdout, report, htmlreport.Type(*reportType)); err != nil {
		fmt.Fprintf(stderr, "render report: %v\n", err)
		return 1
	}

	return 0
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
  secscan report --input audit.json --format html --type admin
  secscan version

Commands:
  audit    detect host/services, run matching checks, print JSON
  detect   detect host/services/modules only, print JSON
  report   render a JSON audit into a client or admin report
  version  print secscan version

Audit flags:
  --all, --all-modules  run every registered module; useful for Ansible batch audits
`))
}
