package publishreport

import (
	"context"
	"strings"
	"testing"
	"time"

	"secscan/internal/audit"
	"secscan/internal/report/htmlreport"
	"secscan/internal/system"
)

type recordingRunner struct {
	commands []Command
}

func (r *recordingRunner) Run(ctx context.Context, command Command) error {
	r.commands = append(r.commands, command)
	return nil
}

func TestFilename(t *testing.T) {
	name, err := Filename(audit.Report{
		Host: system.Info{Hostname: "srv 01.example.pl"},
	}, Options{
		Now:          time.Date(2026, 5, 6, 14, 7, 0, 0, time.UTC),
		RandomSuffix: "abc123",
	})
	if err != nil {
		t.Fatalf("filename: %v", err)
	}

	want := "srv-01.example.pl-2026-05-06-1407-abc123.html"
	if name != want {
		t.Fatalf("expected %s, got %s", want, name)
	}
}

func TestBuildRsyncCommand(t *testing.T) {
	command := BuildRsyncCommand("/tmp/report.html", Options{
		SSHHost:   "reports.example.pl",
		SSHUser:   "lh",
		SSHPort:   40022,
		RemoteDir: "/home/lh/domains/example.pl/public_html/audits",
	}, "host-2026.html")

	if command.Name != "rsync" {
		t.Fatalf("expected rsync command, got %s", command.Name)
	}
	want := []string{
		"-avz",
		"-e",
		"ssh -p 40022",
		"/tmp/report.html",
		"lh@reports.example.pl:/home/lh/domains/example.pl/public_html/audits/host-2026.html",
	}
	if strings.Join(command.Args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected args:\n%q", command.Args)
	}
}

func TestAdminRequiresAllowAdmin(t *testing.T) {
	err := Validate(Options{
		Input:         "audit.json",
		ReportType:    htmlreport.TypeAdmin,
		SSHHost:       "reports.example.pl",
		SSHUser:       "lh",
		SSHPort:       40022,
		RemoteDir:     "/remote",
		PublicBaseURL: "https://example.pl/audits",
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-admin") {
		t.Fatalf("expected allow-admin error, got %v", err)
	}

	err = Validate(Options{
		Input:         "audit.json",
		ReportType:    htmlreport.TypeAdmin,
		AllowAdmin:    true,
		SSHHost:       "reports.example.pl",
		SSHUser:       "lh",
		SSHPort:       40022,
		RemoteDir:     "/remote",
		PublicBaseURL: "https://example.pl/audits",
	})
	if err != nil {
		t.Fatalf("expected admin publish to be allowed, got %v", err)
	}
}

func TestValidateDefaultsToClientReport(t *testing.T) {
	err := Validate(Options{
		Input:         "audit.json",
		SSHHost:       "reports.example.pl",
		SSHUser:       "lh",
		SSHPort:       40022,
		RemoteDir:     "/remote",
		PublicBaseURL: "https://example.pl/audits",
	})
	if err != nil {
		t.Fatalf("expected empty type to default to client, got %v", err)
	}
}

func TestPublicURL(t *testing.T) {
	got := PublicURL("https://example.pl/audits/", "srv-01-2026.html")
	want := "https://example.pl/audits/srv-01-2026.html"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestPublishUploadsReportAndLatest(t *testing.T) {
	runner := &recordingRunner{}
	report := audit.Report{
		Version:     "0.1.0",
		GeneratedAt: "2026-05-06T12:00:00Z",
		Host:        system.Info{Hostname: "srv1"},
		Meta:        map[string]string{},
	}

	url, err := Publish(context.Background(), report, Options{
		Input:         "audit.json",
		ReportType:    htmlreport.TypeClient,
		SSHHost:       "reports.example.pl",
		SSHUser:       "lh",
		SSHPort:       40022,
		RemoteDir:     "/home/lh/audits",
		PublicBaseURL: "https://example.pl/audits",
		Latest:        true,
		TempDir:       t.TempDir(),
		Now:           time.Date(2026, 5, 6, 14, 7, 0, 0, time.UTC),
		RandomSuffix:  "abcd",
	}, runner, nil)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if url != "https://example.pl/audits/srv1-2026-05-06-1407-abcd.html" {
		t.Fatalf("unexpected public URL: %s", url)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("expected report and latest uploads, got %d", len(runner.commands))
	}
	if !strings.HasSuffix(runner.commands[1].Args[len(runner.commands[1].Args)-1], "/latest.html") {
		t.Fatalf("expected latest upload, got %#v", runner.commands[1])
	}
}
