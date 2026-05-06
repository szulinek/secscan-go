package runreport

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secscan/internal/audit"
	"secscan/internal/checks"
	"secscan/internal/execx"
	"secscan/internal/report/htmlreport"
	"secscan/internal/report/pdfreport"
	"secscan/internal/report/publishreport"
	"secscan/internal/report/smtpreport"
)

type fakeRunner map[string]string

func (r fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if output, ok := r[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

type fakePublisher struct {
	called  bool
	options publishreport.Options
}

func (p *fakePublisher) Publish(ctx context.Context, report audit.Report, options publishreport.Options, stdout io.Writer) (string, error) {
	p.called = true
	p.options = options
	return publishreport.PublicURL(options.PublicBaseURL, "published.html"), nil
}

func TestRunFlowWithoutPublishOrEmail(t *testing.T) {
	dir := t.TempDir()
	result, err := Run(context.Background(), Options{
		OutputDir:     dir,
		KeepArtifacts: true,
		Now:           fixedTime(),
	}, testDeps(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, path := range []string{result.AuditPath, result.HTMLPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	if result.PDFPath != "" {
		t.Fatalf("did not expect pdf path, got %s", result.PDFPath)
	}
	if !strings.HasSuffix(filepath.Base(result.AuditPath), "-2026-05-06-1407.json") {
		t.Fatalf("unexpected audit filename: %s", result.AuditPath)
	}
}

func TestRunFlowWithPublish(t *testing.T) {
	publisher := &fakePublisher{}
	result, err := Run(context.Background(), Options{
		OutputDir:     t.TempDir(),
		KeepArtifacts: true,
		Publish:       true,
		PublishOptions: publishreport.Options{
			SSHHost:       "reports.example.pl",
			SSHUser:       "lh",
			SSHPort:       40022,
			RemoteDir:     "/remote",
			PublicBaseURL: "https://example.pl/audits",
		},
		Latest: true,
		Now:    fixedTime(),
	}, testDepsWithPublisher(publisher), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !publisher.called {
		t.Fatal("expected publisher to be called")
	}
	if !publisher.options.Latest {
		t.Fatal("expected latest flag to be passed to publisher")
	}
	if result.PublicURL != "https://example.pl/audits/published.html" {
		t.Fatalf("unexpected public url: %s", result.PublicURL)
	}
}

func TestRunFlowWithEmailLink(t *testing.T) {
	publisher := &fakePublisher{}
	var sent smtpreport.Message
	deps := testDepsWithPublisher(publisher)
	deps.LoadSMTP = func(path string) (smtpreport.Config, error) {
		if path != "config/smtp.json" {
			t.Fatalf("unexpected smtp config: %s", path)
		}
		return smtpreport.Config{Host: "smtp.example.pl", Port: 587, From: "audit@example.pl"}, nil
	}
	deps.SendMail = func(config smtpreport.Config, message smtpreport.Message) error {
		sent = message
		return nil
	}

	_, err := Run(context.Background(), Options{
		OutputDir:     t.TempDir(),
		KeepArtifacts: true,
		Publish:       true,
		PublishOptions: publishreport.Options{
			SSHHost:       "reports.example.pl",
			SSHUser:       "lh",
			SSHPort:       40022,
			RemoteDir:     "/remote",
			PublicBaseURL: "https://example.pl/audits",
		},
		To:  "klient@example.com",
		Now: fixedTime(),
	}, deps, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sent.To) != 1 || sent.To[0] != "klient@example.com" {
		t.Fatalf("unexpected recipients: %#v", sent.To)
	}
	if !strings.Contains(sent.Body, "https://example.pl/audits/published.html") {
		t.Fatalf("expected email body to contain public URL, got %q", sent.Body)
	}
	if len(sent.Attachment) != 0 {
		t.Fatal("link-only email should not include PDF attachment")
	}
}

func TestRunBlocksAdminWithoutAllowAdmin(t *testing.T) {
	_, err := Run(context.Background(), Options{
		OutputDir:     t.TempDir(),
		KeepArtifacts: true,
		ReportType:    htmlreport.TypeAdmin,
		Now:           fixedTime(),
	}, testDeps(), nil)
	if err == nil || !strings.Contains(err.Error(), "--allow-admin") {
		t.Fatalf("expected allow admin error, got %v", err)
	}
}

func testDeps() Dependencies {
	return testDepsWithPublisher(&fakePublisher{})
}

func testDepsWithPublisher(publisher Publisher) Dependencies {
	return Dependencies{
		Runner: fakeRunner{
			"systemctl list-units --type=service --state=running --no-legend --no-pager --plain": "",
		},
		Registry:  checks.NewRegistry(),
		Publisher: publisher,
		LoadSMTP: func(path string) (smtpreport.Config, error) {
			return smtpreport.Config{Host: "smtp.example.pl", Port: 587, From: "audit@example.pl"}, nil
		},
		SendMail: func(config smtpreport.Config, message smtpreport.Message) error {
			return nil
		},
		PDFRenderer: func(w io.Writer, report audit.Report, reportType htmlreport.Type, options pdfreport.Options) error {
			_, err := w.Write([]byte("%PDF-test"))
			return err
		},
	}
}

func fixedTime() time.Time {
	return time.Date(2026, 5, 6, 14, 7, 0, 0, time.UTC)
}

var _ execx.Runner = fakeRunner{}
