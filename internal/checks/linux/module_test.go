package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type mockRunner struct {
	outputs map[string]string
	errors  map[string]error
}

func (r mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if err, ok := r.errors[key]; ok {
		return nil, err
	}
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("%s: executable file not found", name)
}

func TestIPTablesLooksConfigured(t *testing.T) {
	if iptablesLooksConfigured("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n") {
		t.Fatal("default ACCEPT policies should not be treated as configured firewall rules")
	}

	if !iptablesLooksConfigured("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n") {
		t.Fatal("DROP policy and explicit rules should be treated as configured firewall rules")
	}
}

func TestLinuxParsers(t *testing.T) {
	ports := parseSSListeningPorts(strings.Join([]string{
		"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
		`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))`,
		`tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=102,fd=7))`,
	}, "\n"))
	if len(ports) != 1 || ports[0].Port != "22" || ports[0].Process != "sshd" {
		t.Fatalf("unexpected parsed ports: %#v", ports)
	}

	packages := securityUpdatePackages("Inst openssl [1] (1 Debian-Security:12/stable-security [amd64])\nInst curl [1] (1 Debian:12/stable [amd64])", 5)
	if len(packages) != 1 || packages[0] != "openssl" {
		t.Fatalf("unexpected security update packages: %#v", packages)
	}

	sudoFindings := riskySudoersLines("/etc/sudoers.d/admins", "ops ALL=(ALL) NOPASSWD: ALL # ticket 123\nadmin ALL=(ALL) ALL\n")
	if strings.Join(sudoFindings, ";") != "admins:NOPASSWD:ops;admins:ALL=(ALL)ALL:admin" {
		t.Fatalf("unexpected sudo parser output: %#v", sudoFindings)
	}
}

func TestOSVersionCheck(t *testing.T) {
	result := checkOSVersion{}.Run(checks.Context{
		Host: system.Info{OSRelease: map[string]string{
			"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
			"VERSION_ID":       "12",
			"VERSION_CODENAME": "bookworm",
		}},
	})

	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	for _, needle := range []string{"PRETTY_NAME=Debian GNU/Linux 12 (bookworm)", "VERSION_ID=12", "VERSION_CODENAME=bookworm"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %q", needle, result.Evidence)
		}
	}
}

func TestKernelVersionCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner:  mockRunner{outputs: map[string]string{"uname -r": "6.1.0-25-amd64\n"}},
	}

	result := checkKernelVersion{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	if result.Evidence != "kernel=6.1.0-25-amd64" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{errors: map[string]error{"uname -r": errors.New("permission denied")}}
	result = checkKernelVersion{}.Run(ctx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status, got %s", result.Status)
	}
	if result.Evidence != "uname -r failed" {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
}

func TestSecurityUpdatesAvailableCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"apt-get -s -o Debug::NoLocking=true upgrade": strings.Join([]string{
				"Inst openssl [1.1] (1.2 Debian-Security:12/stable-security [amd64])",
				"Inst nginx [1.22] (1.24 Debian:12/stable [amd64])",
			}, "\n"),
		}},
	}

	result := checkSecurityUpdatesAvailable{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	if result.Evidence != "security_updates=1; packages=openssl" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{outputs: map[string]string{"apt-get -s -o Debug::NoLocking=true upgrade": "0 upgraded, 0 newly installed\n"}}
	result = checkSecurityUpdatesAvailable{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	if result.Evidence != "security_updates=0" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	ctx.Host = system.Info{GOOS: "linux", OSRelease: map[string]string{"ID": "alpine"}}
	result = checkSecurityUpdatesAvailable{}.Run(ctx)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable for unsupported distro, got %s", result.Status)
	}
}

func TestUnattendedUpgradesCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"dpkg-query -W -f=${Status} unattended-upgrades": "install ok installed",
		}},
	}
	writeFixtureFile(t, aptPeriodicPaths[0], 0644, `APT::Periodic::Unattended-Upgrade "1";`)

	result := checkUnattendedUpgrades{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "package=unattended-upgrades installed") || !strings.Contains(result.Evidence, "apt periodic") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	writeFixtureFile(t, paths.limitsConfPath, 0644, "* hard nproc 4096\n")
	ctx.Runner = mockRunner{}
	result = checkUnattendedUpgrades{}.Run(ctx)
	if result.Status != checks.StatusFail {
		t.Fatalf("expected fail status when missing, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	assertWarningHasRemediationSteps(t, result)
}

func TestListeningPortsCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"ss -tulpn": strings.Join([]string{
				"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
				`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))`,
				`tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=101,fd=6))`,
				`tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=102,fd=7))`,
			}, "\n"),
		}},
	}

	result := checkListeningPorts{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "tcp/0.0.0.0/22/sshd") || !strings.Contains(result.Evidence, "tcp/::/443/nginx") {
		t.Fatalf("unexpected listening port evidence: %s", result.Evidence)
	}
	if strings.Contains(result.Evidence, "3306") {
		t.Fatalf("loopback listener should not be reported: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{outputs: map[string]string{
		"ss -tulpn": `tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("devsrv",pid=200,fd=3))`,
	}}
	result = checkListeningPorts{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "tcp/0.0.0.0/8080/devsrv") {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	if result.HiddenInClientReport {
		t.Fatal("unexpected public port warning should be visible to client report")
	}
}

func TestConfigPermissionsCheck(t *testing.T) {
	withLinuxFixturePaths(t)
	ctx := checks.Context{Context: context.Background(), Host: linuxHost()}

	result := checkConfigPermissions{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "passwd=mode=0644 owner=") || !strings.Contains(result.Evidence, "sudoers=mode=0440 owner=") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	if err := os.Chmod(configPermissionTargets[1].Path, 0644); err != nil {
		t.Fatalf("chmod shadow fixture: %v", err)
	}
	result = checkConfigPermissions{}.Run(ctx)
	if result.Status != checks.StatusFail {
		t.Fatalf("expected fail status for broad shadow permissions, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "shadow=mode=0644>0640") {
		t.Fatalf("unexpected fail evidence: %s", result.Evidence)
	}

	if err := os.Remove(configPermissionTargets[0].Path); err != nil {
		t.Fatalf("remove passwd fixture: %v", err)
	}
	result = checkConfigPermissions{}.Run(ctx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status for unreadable config, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "passwd=stat_error") {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
}

func TestSudoersRiskyEntriesCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{Context: context.Background(), Host: linuxHost()}

	result := checkSudoersRiskyEntries{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "sudoers_risks=none" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	riskyPath := filepath.Join(paths.sudoersDropInDir, "admins")
	writeFixtureFile(t, riskyPath, 0440, strings.Join([]string{
		"ops ALL=(ALL) NOPASSWD: ALL",
		"admin ALL=(ALL) ALL",
	}, "\n"))
	result = checkSudoersRiskyEntries{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "admins:NOPASSWD:ops") || !strings.Contains(result.Evidence, "admins:ALL=(ALL)ALL:admin") {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}

	if err := os.Remove(paths.sudoersPath); err != nil {
		t.Fatalf("remove sudoers fixture: %v", err)
	}
	result = checkSudoersRiskyEntries{}.Run(ctx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status for unreadable sudoers, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "sudoers=read_error") {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
}

func TestUnknownUsersCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{Context: context.Background(), Host: linuxHost()}

	writeFixtureFile(t, paths.passwdPath, 0644, strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"lh:x:1000:1000:lh:/home/lh:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
	}, "\n"))
	result := checkUnknownUsers{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status for allowlisted users, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "lh:1000:/bin/bash" {
		t.Fatalf("unexpected info evidence: %s", result.Evidence)
	}

	writeFixtureFile(t, paths.passwdPath, 0644, strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"lh:x:1000:1000:lh:/home/lh:/bin/bash",
		"stranger:x:1001:1001:stranger:/home/stranger:/bin/bash",
	}, "\n"))
	result = checkUnknownUsers{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status for unknown user, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Severity != checks.SeverityMedium {
		t.Fatalf("unknown user warning should be medium, got %s", result.Severity)
	}
	if !strings.Contains(result.Evidence, "stranger:1001:/bin/bash") || strings.Contains(result.Evidence, "lh:1000") {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
}

func TestAppArmorStatusCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner:  mockRunner{outputs: map[string]string{"aa-status": "apparmor module is loaded.\n12 profiles are loaded.\n"}},
	}

	result := checkAppArmorStatus{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "aa-status=active" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{outputs: map[string]string{"aa-status": "apparmor module is not loaded.\n"}}
	result = checkAppArmorStatus{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "aa-status=inactive" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{}
	result = checkAppArmorStatus{}.Run(ctx)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "apparmor=not_installed" {
		t.Fatalf("unexpected not_applicable evidence: %s", result.Evidence)
	}
}

func TestAuthLogRecentLoginsCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{Context: context.Background(), Host: linuxHost()}

	writeFixtureFile(t, paths.authLogPath, 0644, strings.Join([]string{
		"Apr 20 10:00:00 host sshd[100]: Accepted publickey for deploy from 203.0.113.10 port 45000 ssh2",
		"Apr 20 10:01:00 host sshd[101]: Failed password for invalid user test from 203.0.113.20 port 45001 ssh2",
	}, "\n"))
	writeFixtureFile(t, paths.authLogRotatedPath, 0644, "")
	result := checkAuthLogRecentLogins{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "accepted_count=1; failed_count=1; invalid_user_count=1; unique_source_ips=2" {
		t.Fatalf("unexpected info evidence: %s", result.Evidence)
	}

	failed := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		failed = append(failed, "Apr 20 10:01:00 host sshd[101]: Failed password for invalid user test from 203.0.113.20 port 45001 ssh2")
	}
	writeFixtureFile(t, paths.authLogPath, 0644, strings.Join(failed, "\n"))
	result = checkAuthLogRecentLogins{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "accepted_count=0; failed_count=101; invalid_user_count=101; unique_source_ips=1" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	assertWarningHasRemediationSteps(t, result)

	invalid := make([]string, 0, 21)
	for i := 0; i < 21; i++ {
		invalid = append(invalid, fmt.Sprintf("Apr 20 10:01:00 host sshd[101]: Invalid user test%d from 203.0.113.%d port 45001", i, i))
	}
	writeFixtureFile(t, paths.authLogPath, 0644, strings.Join(invalid, "\n"))
	result = checkAuthLogRecentLogins{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status for invalid user threshold, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "invalid_user_count=21") || !strings.Contains(result.Evidence, "unique_source_ips=21") {
		t.Fatalf("unexpected invalid user evidence: %s", result.Evidence)
	}

	if err := os.Remove(paths.authLogPath); err != nil {
		t.Fatalf("remove auth log fixture: %v", err)
	}
	if err := os.Remove(paths.authLogRotatedPath); err != nil {
		t.Fatalf("remove rotated auth log fixture: %v", err)
	}
	result = checkAuthLogRecentLogins{}.Run(ctx)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "auth_log=not_found" {
		t.Fatalf("unexpected not_applicable evidence: %s", result.Evidence)
	}
}

func TestForkbombLimitsCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{Context: context.Background(), Host: linuxHost()}

	result := checkForkbombLimits{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "limits.conf:nproc=4096") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}

	writeFixtureFile(t, paths.limitsConfPath, 0644, "# no nproc limit here\n")
	result = checkForkbombLimits{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "nproc_limits=not_found" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	assertWarningHasRemediationSteps(t, result)

	writeFixtureFile(t, paths.cgroupPidsPath, 0644, "512\n")
	result = checkForkbombLimits{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status from cgroup pids limit, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "pids.max=512") {
		t.Fatalf("unexpected cgroup evidence: %s", result.Evidence)
	}
}

func TestProcessSnapshotCheck(t *testing.T) {
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{"ps auxww": strings.Join([]string{
			"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND",
			"root 1 0.1 0.2 1000 100 ? Ss Apr20 00:01 /sbin/init",
			"www-data 200 3.0 4.5 2000 200 ? S Apr20 00:02 php-fpm: pool www",
		}, "\n")}},
	}

	result := checkProcessAnomalies{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "top=www-data:200:cpu=3.0:mem=4.5:php-fpm: pool www") {
		t.Fatalf("unexpected info evidence: %s", result.Evidence)
	}

	ctx.Runner = mockRunner{outputs: map[string]string{"ps auxww": strings.Join([]string{
		"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND",
		"root 300 0.5 0.1 1000 100 ? S Apr20 00:01 /tmp/.cache/runner",
		"mysql 400 8.0 20.0 2000 200 ? S Apr20 00:02 /usr/sbin/mysqld",
	}, "\n")}}
	result = checkProcessAnomalies{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Severity != checks.SeverityMedium {
		t.Fatalf("suspicious process warning should be medium, got %s", result.Severity)
	}
	if !strings.Contains(result.Evidence, "suspicious=root:300") || !strings.Contains(result.Evidence, "/tmp/.cache/runner") {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	assertWarningHasRemediationSteps(t, result)

	ctx.Runner = mockRunner{outputs: map[string]string{"ps auxww": strings.Join([]string{
		"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND",
		"root 301 0.5 0.1 1000 100 ? S Apr20 00:01 /home/lh/.local/worker",
	}, "\n")}}
	result = checkProcessAnomalies{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status for unusual root path, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "/home/lh/.local/worker") {
		t.Fatalf("unexpected unusual path evidence: %s", result.Evidence)
	}
}

func TestFirewallStatusPassWarnError(t *testing.T) {
	base := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
	}

	passCtx := base
	passCtx.Services = []system.Service{{Unit: "nftables.service"}}
	passCtx.Runner = mockRunner{}
	result := checkFirewallStatus{}.Run(passCtx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "running_service=nftables.service") {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}
	if result.Summary != "An active host firewall signal was detected." {
		t.Fatalf("unexpected pass summary: %s", result.Summary)
	}
	if strings.Contains(result.Summary, "No active") {
		t.Fatalf("pass summary should not contain stale warn text: %s", result.Summary)
	}

	warnCtx := base
	warnCtx.Runner = mockRunner{outputs: map[string]string{
		"ufw status":       "Status: inactive\n",
		"nft list ruleset": "",
		"iptables -S":      "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
	}}
	result = checkFirewallStatus{}.Run(warnCtx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.HasPrefix(result.Evidence, "active_signals=none") {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	if result.Summary != "No active host firewall signal was detected." {
		t.Fatalf("unexpected warn summary: %s", result.Summary)
	}
	if strings.Contains(strings.ToLower(result.Summary+" "+result.ClientSummary), "brute-force") {
		t.Fatalf("firewall messages should not mention protection daemon: %s / %s", result.Summary, result.ClientSummary)
	}

	errorCtx := base
	errorCtx.Runner = mockRunner{errors: map[string]error{
		"ufw status":       errors.New("permission denied"),
		"nft list ruleset": errors.New("permission denied"),
		"iptables -S":      errors.New("permission denied"),
	}}
	result = checkFirewallStatus{}.Run(errorCtx)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "ufw=probe_error") {
		t.Fatalf("unexpected error evidence: %s", result.Evidence)
	}
	if strings.Contains(result.Evidence, "active_signals=none") {
		t.Fatalf("error evidence should not contain stale warn evidence: %s", result.Evidence)
	}
}

func TestProtectionDaemonPassWarn(t *testing.T) {
	ctx := checks.Context{
		Context:  context.Background(),
		Host:     linuxHost(),
		Services: []system.Service{{Unit: "fail2ban.service"}},
	}

	result := checkProtectionDaemon{}.Run(ctx)
	if result.Status != checks.StatusPass {
		t.Fatalf("expected pass status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "running_service=fail2ban.service" {
		t.Fatalf("unexpected pass evidence: %s", result.Evidence)
	}
	assertNoFirewallText(t, result)

	ctx.Services = nil
	result = checkProtectionDaemon{}.Run(ctx)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn status, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if result.Evidence != "protection_daemon=not_detected" {
		t.Fatalf("unexpected warn evidence: %s", result.Evidence)
	}
	if result.Summary != "No fail2ban or CrowdSec service was detected as running." {
		t.Fatalf("unexpected warn summary: %s", result.Summary)
	}
	assertNoFirewallText(t, result)
}

func TestXTGeoIPModuleCheck(t *testing.T) {
	paths := withLinuxFixturePaths(t)
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"lsmod":    "xt_geoip 16384 1\n",
			"uname -r": "6.1.0-test\n",
		}},
	}

	result := checkXTGeoIPModule{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status when xt_geoip is present, got %s", result.Status)
	}
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "lsmod=xt_geoip") {
		t.Fatalf("unexpected geoip evidence: %s", result.Evidence)
	}

	writeFixtureFile(t, paths.iptablesMatchesPath, 0644, "geoip\n")
	ctx.Runner = mockRunner{outputs: map[string]string{"lsmod": "", "uname -r": "6.1.0-test\n"}}
	result = checkXTGeoIPModule{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status from ip_tables_matches, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "ip_tables_matches=geoip") {
		t.Fatalf("unexpected iptables matches evidence: %s", result.Evidence)
	}

	if err := os.Remove(paths.iptablesMatchesPath); err != nil {
		t.Fatalf("remove iptables matches fixture: %v", err)
	}
	kernelDir := filepath.Join(paths.libModulesDir, "6.1.0-test", "kernel", "net", "netfilter")
	if err := os.MkdirAll(kernelDir, 0755); err != nil {
		t.Fatalf("create kernel module fixture: %v", err)
	}
	writeFixtureFile(t, filepath.Join(kernelDir, "xt_geoip.ko"), 0644, "")
	result = checkXTGeoIPModule{}.Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status from module tree, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "module_tree=") {
		t.Fatalf("unexpected module tree evidence: %s", result.Evidence)
	}

	if err := os.Remove(filepath.Join(kernelDir, "xt_geoip.ko")); err != nil {
		t.Fatalf("remove geoip module fixture: %v", err)
	}
	result = checkXTGeoIPModule{}.Run(ctx)
	if result.Status != checks.StatusNotApplicable {
		t.Fatalf("expected not_applicable when absent, got %s", result.Status)
	}
	if result.Evidence != "xt_geoip=not_detected" {
		t.Fatalf("unexpected not_applicable evidence: %s", result.Evidence)
	}
}

func TestLinuxModuleContainsAllBaselineChecks(t *testing.T) {
	ids := map[string]struct{}{}
	for _, check := range NewModule().Checks() {
		ids[check.ID()] = struct{}{}
	}

	expected := []string{
		"linux.os_version",
		"linux.kernel_version",
		"linux.unattended_upgrades",
		"linux.security_updates_available",
		"linux.firewall_status",
		"linux.listening_ports",
		"linux.unknown_users",
		"linux.config_permissions",
		"linux.process_anomalies",
		"linux.sudoers_risky_entries",
		"linux.forkbomb_limits",
		"linux.xt_geoip_module",
		"linux.apparmor_status",
		"linux.protection_daemon",
		"linux.auth_log_recent_logins",
	}
	for _, id := range expected {
		if _, ok := ids[id]; !ok {
			t.Fatalf("missing Linux baseline check %s", id)
		}
	}
	if len(ids) != len(expected) {
		t.Fatalf("expected %d Linux checks, got %d: %#v", len(expected), len(ids), ids)
	}
}

func TestLinuxChecksDoNotLeaveDuplicateOrStaleMessages(t *testing.T) {
	withLinuxFixturePaths(t)
	ctx := checks.Context{
		Context: context.Background(),
		Host:    linuxHost(),
		Runner: mockRunner{outputs: map[string]string{
			"uname -r": "6.1.0-25-amd64\n",
			"apt-get -s -o Debug::NoLocking=true upgrade":      "0 upgraded, 0 newly installed\n",
			"dpkg-query -W -f=${Status} unattended-upgrades":   "install ok installed",
			"systemctl is-enabled unattended-upgrades.service": "enabled\n",
			"ss -tulpn":        `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))`,
			"aa-status":        "apparmor module is loaded.\n12 profiles are loaded.\n",
			"ps auxww":         "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.1 0.2 1000 100 ? Ss Apr20 00:01 /sbin/init\n",
			"ufw status":       "Status: inactive\n",
			"nft list ruleset": "",
			"iptables -S":      "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
		}},
	}

	for _, check := range []checks.Check{
		checkOSVersion{},
		checkKernelVersion{},
		checkSecurityUpdatesAvailable{},
		checkUnattendedUpgrades{},
		checkFirewallStatus{},
		checkProtectionDaemon{},
		checkListeningPorts{},
		checkConfigPermissions{},
		checkSudoersRiskyEntries{},
		checkUnknownUsers{},
		checkAppArmorStatus{},
		checkAuthLogRecentLogins{},
		checkForkbombLimits{},
		checkProcessAnomalies{},
		checkXTGeoIPModule{},
	} {
		result := check.Run(ctx)
		assertCompleteResult(t, result)
		if strings.Contains(strings.ToLower(result.Summary), "firewall") && result.ID == "linux.protection_daemon" {
			t.Fatalf("protection daemon summary mentions firewall: %s", result.Summary)
		}
	}
}

type fixturePaths struct {
	passwdPath          string
	sudoersPath         string
	sudoersDropInDir    string
	authLogPath         string
	authLogRotatedPath  string
	limitsConfPath      string
	limitsDropInDir     string
	cgroupPidsPath      string
	iptablesMatchesPath string
	libModulesDir       string
}

func withLinuxFixturePaths(t *testing.T) fixturePaths {
	t.Helper()

	dir := t.TempDir()
	sshDir := filepath.Join(dir, "ssh")
	sudoersDir := filepath.Join(dir, "sudoers.d")
	limitsDir := filepath.Join(dir, "limits.d")
	cgroupDir := filepath.Join(dir, "cgroup")
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("create ssh fixture dir: %v", err)
	}
	if err := os.MkdirAll(sudoersDir, 0700); err != nil {
		t.Fatalf("create sudoers fixture dir: %v", err)
	}
	if err := os.MkdirAll(limitsDir, 0700); err != nil {
		t.Fatalf("create limits fixture dir: %v", err)
	}
	if err := os.MkdirAll(cgroupDir, 0700); err != nil {
		t.Fatalf("create cgroup fixture dir: %v", err)
	}
	if err := os.MkdirAll(modulesDir, 0700); err != nil {
		t.Fatalf("create modules fixture dir: %v", err)
	}

	paths := fixturePaths{
		passwdPath:          filepath.Join(dir, "passwd"),
		sudoersPath:         filepath.Join(dir, "sudoers"),
		sudoersDropInDir:    sudoersDir,
		authLogPath:         filepath.Join(dir, "auth.log"),
		authLogRotatedPath:  filepath.Join(dir, "auth.log.1"),
		limitsConfPath:      filepath.Join(dir, "limits.conf"),
		limitsDropInDir:     limitsDir,
		cgroupPidsPath:      filepath.Join(cgroupDir, "pids.max"),
		iptablesMatchesPath: filepath.Join(dir, "ip_tables_matches"),
		libModulesDir:       modulesDir,
	}
	targets := []configPermissionTarget{
		{Key: "passwd", Path: paths.passwdPath, MaxMode: 0644},
		{Key: "shadow", Path: filepath.Join(dir, "shadow"), MaxMode: 0640, Critical: true},
		{Key: "sudoers", Path: paths.sudoersPath, MaxMode: 0440, Critical: true},
		{Key: "sshd_config", Path: filepath.Join(sshDir, "sshd_config"), MaxMode: 0644},
	}
	writeFixtureFile(t, targets[0].Path, 0644, "root:x:0:0:root:/root:/bin/bash\n")
	writeFixtureFile(t, targets[1].Path, 0640, "root:*:19000:0:99999:7:::\n")
	writeFixtureFile(t, targets[2].Path, 0440, "root ALL=(root) /usr/bin/systemctl\n")
	writeFixtureFile(t, targets[3].Path, 0644, "PermitRootLogin no\n")
	writeFixtureFile(t, paths.authLogPath, 0644, "Apr 20 10:00:00 host sshd[100]: Accepted publickey for deploy from 203.0.113.10 port 45000 ssh2\n")
	writeFixtureFile(t, paths.authLogRotatedPath, 0644, "")
	writeFixtureFile(t, paths.limitsConfPath, 0644, "* hard nproc 4096\n")

	originalTargets := configPermissionTargets
	originalSudoersPath := sudoersPath
	originalSudoersDropInPath := sudoersDropInPath
	originalPasswdPath := passwdPath
	originalAuthLogPaths := authLogPaths
	originalLimitsConfPath := limitsConfPath
	originalLimitsDropInPath := limitsDropInPath
	originalAptPeriodicPaths := aptPeriodicPaths
	originalCgroupPidsPaths := cgroupPidsPaths
	originalIPTablesMatchesPath := ipTablesMatchesPath
	originalLibModulesPath := libModulesPath
	originalNowFunc := nowFunc
	configPermissionTargets = targets
	sudoersPath = paths.sudoersPath
	sudoersDropInPath = paths.sudoersDropInDir
	passwdPath = paths.passwdPath
	authLogPaths = []string{paths.authLogPath, paths.authLogRotatedPath}
	limitsConfPath = paths.limitsConfPath
	limitsDropInPath = paths.limitsDropInDir
	aptPeriodicPaths = []string{filepath.Join(dir, "20auto-upgrades"), filepath.Join(dir, "50unattended-upgrades")}
	cgroupPidsPaths = []string{paths.cgroupPidsPath}
	ipTablesMatchesPath = paths.iptablesMatchesPath
	libModulesPath = paths.libModulesDir
	nowFunc = func() time.Time {
		return time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	}
	t.Cleanup(func() {
		configPermissionTargets = originalTargets
		sudoersPath = originalSudoersPath
		sudoersDropInPath = originalSudoersDropInPath
		passwdPath = originalPasswdPath
		authLogPaths = originalAuthLogPaths
		limitsConfPath = originalLimitsConfPath
		limitsDropInPath = originalLimitsDropInPath
		aptPeriodicPaths = originalAptPeriodicPaths
		cgroupPidsPaths = originalCgroupPidsPaths
		ipTablesMatchesPath = originalIPTablesMatchesPath
		libModulesPath = originalLibModulesPath
		nowFunc = originalNowFunc
	})

	return paths
}

func writeFixtureFile(t *testing.T, path string, mode os.FileMode, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod fixture %s: %v", path, err)
	}
}

func linuxHost() system.Info {
	return system.Info{
		GOOS: "linux",
		OSRelease: map[string]string{
			"ID":               "debian",
			"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
			"VERSION_ID":       "12",
			"VERSION_CODENAME": "bookworm",
		},
	}
}

func assertCompleteResult(t *testing.T, result checks.Result) {
	t.Helper()
	missing := []string{}
	if result.Category == "" {
		missing = append(missing, "category")
	}
	if result.Severity == "" {
		missing = append(missing, "severity")
	}
	if result.Status == "" {
		missing = append(missing, "status")
	}
	if result.Title == "" {
		missing = append(missing, "title")
	}
	if result.Summary == "" {
		missing = append(missing, "summary")
	}
	if result.ClientSummary == "" {
		missing = append(missing, "client_summary")
	}
	if result.AdminDetails == "" {
		missing = append(missing, "admin_details")
	}
	if result.Impact == "" {
		missing = append(missing, "impact")
	}
	if result.Recommendation == "" {
		missing = append(missing, "recommendation")
	}
	if result.Remediation == "" {
		missing = append(missing, "remediation")
	}
	if result.Evidence == "" {
		missing = append(missing, "evidence")
	}
	if len(missing) > 0 {
		t.Fatalf("%s missing fields: %s", result.ID, strings.Join(missing, ", "))
	}
}

func assertNoFirewallText(t *testing.T, result checks.Result) {
	t.Helper()
	combined := strings.ToLower(strings.Join([]string{
		result.Title,
		result.Summary,
		result.ClientSummary,
		result.AdminDetails,
		result.Impact,
		result.Recommendation,
		result.Remediation,
		result.Evidence,
	}, " "))
	if strings.Contains(combined, "firewall") {
		t.Fatalf("%s should not mention firewall: %s", result.ID, combined)
	}
}

func assertWarningHasRemediationSteps(t *testing.T, result checks.Result) {
	t.Helper()
	if result.Status != checks.StatusWarn && result.Status != checks.StatusFail {
		t.Fatalf("%s is not a risk result: %s", result.ID, result.Status)
	}
	if len(result.RemediationSteps) == 0 {
		t.Fatalf("%s should include remediation steps for risk status", result.ID)
	}
}
