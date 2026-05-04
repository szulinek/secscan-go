package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"secscan/internal/audit"
	"secscan/internal/execx"
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
	if err := flags.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := audit.Run(ctx, execx.LocalRunner{}, audit.DefaultRegistry())
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
  secscan audit [--timeout 30s]
  secscan detect [--timeout 30s]
  secscan version

Commands:
  audit    detect host/services, run matching checks, print JSON
  detect   detect host/services/modules only, print JSON
  version  print secscan version
`))
}
