package publishreport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"secscan/internal/audit"
	"secscan/internal/report/htmlreport"
)

type Options struct {
	Input         string
	ReportType    htmlreport.Type
	AllowAdmin    bool
	SSHHost       string
	SSHUser       string
	SSHPort       int
	RemoteDir     string
	PublicBaseURL string
	Latest        bool
	TempDir       string
	Now           time.Time
	RandomSuffix  string
}

type Command struct {
	Name string
	Args []string
}

type Runner interface {
	Run(ctx context.Context, command Command) error
}

type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, command Command) error {
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		details := strings.TrimSpace(string(output))
		if details != "" {
			return fmt.Errorf("%s failed: %w: %s", command.Name, err, details)
		}
		return fmt.Errorf("%s failed: %w", command.Name, err)
	}
	return nil
}

func Publish(ctx context.Context, report audit.Report, options Options, runner Runner, stdout io.Writer) (string, error) {
	options = Normalize(options)
	if err := Validate(options); err != nil {
		return "", err
	}
	if runner == nil {
		runner = LocalRunner{}
	}

	filename, err := Filename(report, options)
	if err != nil {
		return "", err
	}

	tempDir := options.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	localPath := filepath.Join(tempDir, filename)
	file, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("create temp report: %w", err)
	}
	removePath := localPath
	defer os.Remove(removePath)

	if err := htmlreport.Render(file, report, options.ReportType); err != nil {
		file.Close()
		return "", fmt.Errorf("render html report: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close temp report: %w", err)
	}

	if err := runner.Run(ctx, BuildRsyncCommand(localPath, options, filename)); err != nil {
		return "", err
	}
	if options.Latest {
		if err := runner.Run(ctx, BuildRsyncCommand(localPath, options, "latest.html")); err != nil {
			return "", err
		}
	}

	publicURL := PublicURL(options.PublicBaseURL, filename)
	if stdout != nil {
		fmt.Fprintln(stdout, publicURL)
	}
	return publicURL, nil
}

func Validate(options Options) error {
	options = Normalize(options)
	if options.Input == "" {
		return errors.New("missing required --input audit.json")
	}
	if options.ReportType != htmlreport.TypeClient && options.ReportType != htmlreport.TypeAdmin {
		return fmt.Errorf("unsupported report type: %s", options.ReportType)
	}
	if options.ReportType == htmlreport.TypeAdmin && !options.AllowAdmin {
		return errors.New("admin report publishing requires --allow-admin")
	}
	if strings.TrimSpace(options.SSHHost) == "" {
		return errors.New("missing required --ssh-host")
	}
	if strings.TrimSpace(options.SSHUser) == "" {
		return errors.New("missing required --ssh-user")
	}
	if options.SSHPort <= 0 {
		return errors.New("missing required --ssh-port")
	}
	if strings.TrimSpace(options.RemoteDir) == "" {
		return errors.New("missing required --remote-dir")
	}
	if strings.TrimSpace(options.PublicBaseURL) == "" {
		return errors.New("missing required --public-base-url")
	}
	return nil
}

func Normalize(options Options) Options {
	if options.ReportType == "" {
		options.ReportType = htmlreport.TypeClient
	}
	return options
}

func Filename(report audit.Report, options Options) (string, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	randomPart := strings.TrimSpace(options.RandomSuffix)
	if randomPart == "" {
		value, err := randomHex(4)
		if err != nil {
			return "", err
		}
		randomPart = value
	}

	host := reportHostname(report)
	return fmt.Sprintf("%s-%s-%s.html", sanitizeFilenamePart(host), now.Format("2006-01-02-1504"), sanitizeFilenamePart(randomPart)), nil
}

func BuildRsyncCommand(localPath string, options Options, remoteFilename string) Command {
	remote := fmt.Sprintf("%s@%s:%s", options.SSHUser, options.SSHHost, remotePath(options.RemoteDir, remoteFilename))
	return Command{
		Name: "rsync",
		Args: []string{
			"-avz",
			"-e",
			fmt.Sprintf("ssh -p %d", options.SSHPort),
			localPath,
			remote,
		},
	}
}

func PublicURL(baseURL, filename string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	escaped := (&url.URL{Path: filename}).EscapedPath()
	return base + "/" + strings.TrimPrefix(escaped, "/")
}

func reportHostname(report audit.Report) string {
	for _, value := range []string{
		report.Meta["hostname"],
		report.Meta["host"],
		report.Host.Hostname,
	} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	if len(report.Host.IPAddresses) > 0 && strings.TrimSpace(report.Host.IPAddresses[0]) != "" {
		return report.Host.IPAddresses[0]
	}
	return "host"
}

func remotePath(remoteDir, filename string) string {
	return strings.TrimRight(remoteDir, "/") + "/" + filename
}

var unsafeFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	value = unsafeFilenameChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, ".-_")
	if value == "" {
		return "host"
	}
	return value
}

func randomHex(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate random suffix: %w", err)
	}
	return hex.EncodeToString(data), nil
}
