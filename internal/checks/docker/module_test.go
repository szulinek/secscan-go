package docker

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

type mockRunner struct {
	outputs map[string]string
	errors  map[string]error
	counts  map[string]int
}

func (r *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[key]++
	if err, ok := r.errors[key]; ok {
		return nil, err
	}
	if output, ok := r.outputs[key]; ok {
		return []byte(output), nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

type dockerFixturePaths struct {
	root       string
	socket     string
	binary     string
	data       string
	overlay2   string
	containers string
	daemonJSON string
}

func TestDaemonDetectedEvidence(t *testing.T) {
	paths := withDockerFixture(t)
	ctx := dockerContext(&mockRunner{})

	result := checkDaemonDetected{}.Run(ctx)
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	if result.Evidence != "service=docker.service" {
		t.Fatalf("expected service evidence, got %q", result.Evidence)
	}

	ctx.Services = nil
	result = checkDaemonDetected{}.Run(ctx)
	assertCompleteResult(t, result)
	if !strings.Contains(result.Evidence, "binary="+paths.binary) {
		t.Fatalf("expected binary evidence, got %q", result.Evidence)
	}
}

func TestVersionCheckParsesDockerVersionJSON(t *testing.T) {
	withDockerFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"docker version --format {{json .}}": dockerVersionJSON,
	}}

	result := checkVersion{}.Run(dockerContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "client_version=25.0.3") || !strings.Contains(result.Evidence, "server_version=25.0.3") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestSocketPermissionsStandardDockerGroupPasses(t *testing.T) {
	paths := withDockerFixture(t)
	shortDir, err := os.MkdirTemp("", "dockersock")
	if err != nil {
		t.Fatalf("create short socket dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(shortDir)
	})
	paths.socket = filepath.Join(shortDir, "docker.sock")
	dockerSocketPath = paths.socket
	dockerSocketPaths = []string{paths.socket}
	listener := createUnixSocket(t, paths.socket)
	defer listener.Close()
	mockSocketOwnerGroup(t, "root(0)", "docker(999)")
	if err := os.Chmod(paths.socket, 0660); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	result := checkSocketPermissions{}.Run(dockerContext(&mockRunner{outputs: map[string]string{
		"ss -lntp": "",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusPass || result.Severity != checks.SeverityLow {
		t.Fatalf("expected low pass, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "mode=0660") || !strings.Contains(result.Evidence, "tcp_listeners=none") {
		t.Fatalf("expected socket mode and TCP evidence, got %s", result.Evidence)
	}
	if !strings.Contains(result.AdminDetails, "Members of docker group effectively have root-equivalent access.") {
		t.Fatalf("expected docker group admin note, got %s", result.AdminDetails)
	}
}

func TestSocketPermissionsWorldWritableWarnsHigh(t *testing.T) {
	withDockerFixture(t)
	socketPath := shortSocketPath(t, "docker.sock")
	dockerSocketPath = socketPath
	dockerSocketPaths = []string{socketPath}
	listener := createUnixSocket(t, socketPath)
	defer listener.Close()
	mockSocketOwnerGroup(t, "root(0)", "docker(999)")
	if err := os.Chmod(socketPath, 0666); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	result := checkSocketPermissions{}.Run(dockerContext(&mockRunner{outputs: map[string]string{
		"ss -lntp": "",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "mode=0666") {
		t.Fatalf("expected mode evidence, got %s", result.Evidence)
	}
}

func TestSocketPermissionsFailsOnPublicDockerTCPAPI(t *testing.T) {
	withDockerFixture(t)
	socketPath := shortSocketPath(t, "docker.sock")
	dockerSocketPath = socketPath
	dockerSocketPaths = []string{socketPath}
	listener := createUnixSocket(t, socketPath)
	defer listener.Close()
	mockSocketOwnerGroup(t, "root(0)", "docker(999)")
	if err := os.Chmod(socketPath, 0660); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	result := checkSocketPermissions{}.Run(dockerContext(&mockRunner{outputs: map[string]string{
		"ss -lntp": "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
			"tcp LISTEN 0 4096 0.0.0.0:2376 0.0.0.0:* users:((\"dockerd\",pid=100,fd=3))\n",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusFail || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high fail, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "tcp://0.0.0.0:2376") {
		t.Fatalf("expected TCP listener evidence, got %s", result.Evidence)
	}
}

func TestSocketPermissionsWarnsOnCustomSocketPath(t *testing.T) {
	withDockerFixture(t)
	expectedPath := shortSocketPath(t, "expected.sock")
	customPath := shortSocketPath(t, "custom.sock")
	dockerSocketPaths = []string{expectedPath}
	dockerSocketPath = customPath
	listener := createUnixSocket(t, customPath)
	defer listener.Close()
	mockSocketOwnerGroup(t, "root(0)", "docker(999)")
	if err := os.Chmod(customPath, 0660); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	result := checkSocketPermissions{}.Run(dockerContext(&mockRunner{outputs: map[string]string{
		"ss -lntp": "",
	}}))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "path="+customPath) {
		t.Fatalf("expected custom path evidence, got %s", result.Evidence)
	}
}

func TestExposedTCPSocketFailsOnPublic2375(t *testing.T) {
	paths := withDockerFixture(t)
	writeFile(t, paths.daemonJSON, `{"hosts":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"]}`)
	runner := &mockRunner{outputs: map[string]string{
		"ss -tulpn": "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
			"tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:((\"dockerd\",pid=100,fd=3))\n",
		"systemctl show docker.service -p ExecStart --value": "/usr/bin/dockerd -H fd://",
	}}

	result := checkExposedTCPSocket{}.Run(dockerContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusFail || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high fail, got %s/%s (%s)", result.Status, result.Severity, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "tcp://0.0.0.0:2375") {
		t.Fatalf("expected exposed endpoint evidence, got %s", result.Evidence)
	}
}

func TestExposedTCPSocketWarnsOnLocalhost(t *testing.T) {
	withDockerFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"ss -tulpn": "tcp LISTEN 0 4096 127.0.0.1:2375 0.0.0.0:* users:((\"dockerd\",pid=100,fd=3))\n",
		"systemctl show docker.service -p ExecStart --value": "/usr/bin/dockerd -H tcp://127.0.0.1:2375;",
	}}

	result := checkExposedTCPSocket{}.Run(dockerContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s (%s)", result.Status, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "tcp://127.0.0.1:2375") {
		t.Fatalf("expected localhost endpoint evidence, got %s", result.Evidence)
	}
}

func TestPrivilegedContainers(t *testing.T) {
	result := checkPrivilegedContainers{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", result.Status, result.Severity)
	}
	for _, needle := range []string{"privileged-app", "alpine:latest"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %s", needle, result.Evidence)
		}
	}
}

func TestCriticalHostMounts(t *testing.T) {
	result := checkHostMounts{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityHigh {
		t.Fatalf("expected high warn, got %s/%s", result.Status, result.Severity)
	}
	for _, needle := range []string{"/var/run/docker.sock", "/etc", "privileged-app"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %s", needle, result.Evidence)
		}
	}
}

func TestHostNetwork(t *testing.T) {
	result := checkHostNetwork{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "image=alpine:latest") {
		t.Fatalf("expected image evidence, got %s", result.Evidence)
	}
}

func TestDangerousCapabilities(t *testing.T) {
	result := checkDangerousCapabilities{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s", result.Status)
	}
	for _, needle := range []string{"SYS_ADMIN", "NET_ADMIN"} {
		if !strings.Contains(result.Evidence, needle) {
			t.Fatalf("expected evidence to contain %q, got %s", needle, result.Evidence)
		}
	}
}

func TestNoNewPrivileges(t *testing.T) {
	result := checkNoNewPrivileges{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "affected_count=1") || !strings.Contains(result.Evidence, "privileged-app") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestLatestImageTag(t *testing.T) {
	result := checkImageTagLatest{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityLow {
		t.Fatalf("expected low warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "image=alpine:latest") {
		t.Fatalf("expected latest image evidence, got %s", result.Evidence)
	}
}

func TestRootUserContainer(t *testing.T) {
	result := checkContainerUserRoot{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "affected_count=1") || !strings.Contains(result.Evidence, "user=empty") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestRestartPolicy(t *testing.T) {
	result := checkRestartPolicy{cache: &containerCache{}}.Run(dockerAPIContext(t, dockerInspectJSON))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn || result.Severity != checks.SeverityLow {
		t.Fatalf("expected low warn, got %s/%s", result.Status, result.Severity)
	}
	if !strings.Contains(result.Evidence, "restart_policy=none") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestUnusedDataWarnsAboveThreshold(t *testing.T) {
	withDockerFixture(t)
	runner := &mockRunner{outputs: map[string]string{
		"docker system df": strings.Join([]string{
			"TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE",
			"Images          10        2         40GiB     25GiB (62%)",
			"Containers      2         2         100MiB    0B (0%)",
			"Local Volumes   1         1         5GiB      0B (0%)",
			"Build Cache     4         0         2GiB      0B",
		}, "\n"),
	}}

	result := checkUnusedData{}.Run(dockerContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusWarn {
		t.Fatalf("expected warn, got %s (%s)", result.Status, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "images_reclaimable=25GiB") {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}

func TestOverlay2AndLogThresholds(t *testing.T) {
	paths := withDockerFixture(t)
	logDir := filepath.Join(paths.containers, "abc")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("create log dir: %v", err)
	}
	logPath := filepath.Join(logDir, "abc-json.log")
	writeSparseFile(t, logPath, bytesGiB+1)

	logResult := checkContainerLogsLarge{}.Run(dockerContext(&mockRunner{}))
	assertCompleteResult(t, logResult)
	if logResult.Status != checks.StatusWarn {
		t.Fatalf("expected log warn, got %s (%s)", logResult.Status, logResult.Evidence)
	}
	if !strings.Contains(logResult.Evidence, "abc-json.log") {
		t.Fatalf("unexpected log evidence: %s", logResult.Evidence)
	}

	layer := filepath.Join(paths.overlay2, "layer", "diff")
	if err := os.MkdirAll(filepath.Dir(layer), 0755); err != nil {
		t.Fatalf("create overlay dir: %v", err)
	}
	writeSparseFile(t, layer, 31*bytesGiB)
	overlayResult := checkOverlay2Usage{}.Run(dockerContext(&mockRunner{}))
	assertCompleteResult(t, overlayResult)
	if overlayResult.Status != checks.StatusWarn || overlayResult.Severity != checks.SeverityMedium {
		t.Fatalf("expected medium overlay warn, got %s/%s (%s)", overlayResult.Status, overlayResult.Severity, overlayResult.Evidence)
	}

	writeSparseFile(t, layer, 81*bytesGiB)
	overlayResult = checkOverlay2Usage{}.Run(dockerContext(&mockRunner{}))
	assertCompleteResult(t, overlayResult)
	if overlayResult.Status != checks.StatusWarn || overlayResult.Severity != checks.SeverityHigh {
		t.Fatalf("expected high overlay warn, got %s/%s (%s)", overlayResult.Status, overlayResult.Severity, overlayResult.Evidence)
	}
}

func TestDockerAPIPermissionError(t *testing.T) {
	withDockerFixture(t)
	runner := &mockRunner{errors: map[string]error{
		"docker version --format {{json .}}": fmt.Errorf("permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"),
	}}

	result := checkVersion{}.Run(dockerContext(runner))
	assertCompleteResult(t, result)
	if result.Status != checks.StatusError {
		t.Fatalf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Evidence, "permission_denied") {
		t.Fatalf("expected permission evidence, got %s", result.Evidence)
	}
}

func dockerContext(runner *mockRunner) checks.Context {
	return checks.Context{
		Context: context.Background(),
		Runner:  runner,
		Host: system.Info{
			GOOS: "linux",
		},
		Services: []system.Service{{Unit: "docker.service"}},
	}
}

func dockerAPIContext(t *testing.T, inspectJSON string) checks.Context {
	t.Helper()
	withDockerFixture(t)
	return dockerContext(&mockRunner{outputs: map[string]string{
		"docker ps --format {{.ID}}":                "abc123456789\nsafe987654321\n",
		"docker inspect abc123456789 safe987654321": inspectJSON,
	}})
}

func withDockerFixture(t *testing.T) dockerFixturePaths {
	t.Helper()

	root := t.TempDir()
	paths := dockerFixturePaths{
		root:       root,
		socket:     filepath.Join(root, "var", "run", "docker.sock"),
		binary:     filepath.Join(root, "usr", "bin", "docker"),
		data:       filepath.Join(root, "var", "lib", "docker"),
		overlay2:   filepath.Join(root, "var", "lib", "docker", "overlay2"),
		containers: filepath.Join(root, "var", "lib", "docker", "containers"),
		daemonJSON: filepath.Join(root, "etc", "docker", "daemon.json"),
	}

	for _, dir := range []string{
		filepath.Dir(paths.binary),
		paths.data,
		paths.overlay2,
		paths.containers,
		filepath.Dir(paths.daemonJSON),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("create fixture dir %s: %v", dir, err)
		}
	}
	writeFile(t, paths.binary, "#!/bin/sh\n")

	originalSocketPath := dockerSocketPath
	originalDataPath := dockerDataPath
	originalOverlay2Path := dockerOverlay2Path
	originalContainersPath := dockerContainersPath
	originalDaemonConfigPath := dockerDaemonConfigPath
	originalBinaryPaths := dockerBinaryPaths
	originalSocketPaths := dockerSocketPaths
	originalOwnerGroupLookup := ownerGroupLookup
	originalLookPath := lookPath
	dockerSocketPath = paths.socket
	dockerDataPath = paths.data
	dockerOverlay2Path = paths.overlay2
	dockerContainersPath = paths.containers
	dockerDaemonConfigPath = paths.daemonJSON
	dockerBinaryPaths = []string{paths.binary}
	dockerSocketPaths = []string{paths.socket}
	lookPath = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() {
		dockerSocketPath = originalSocketPath
		dockerDataPath = originalDataPath
		dockerOverlay2Path = originalOverlay2Path
		dockerContainersPath = originalContainersPath
		dockerDaemonConfigPath = originalDaemonConfigPath
		dockerBinaryPaths = originalBinaryPaths
		dockerSocketPaths = originalSocketPaths
		ownerGroupLookup = originalOwnerGroupLookup
		lookPath = originalLookPath
	})

	return paths
}

func createUnixSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	return listener
}

func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dockersock")
	if err != nil {
		t.Fatalf("create short socket dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, name)
}

func mockSocketOwnerGroup(t *testing.T, owner, group string) {
	t.Helper()
	previous := ownerGroupLookup
	ownerGroupLookup = func(fs.FileInfo) (string, string) {
		return owner, group
	}
	t.Cleanup(func() {
		ownerGroupLookup = previous
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create parent for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func writeSparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create parent for %s: %v", path, err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create sparse file %s: %v", path, err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatalf("truncate sparse file %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close sparse file %s: %v", path, err)
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
	if result.Automation.Shell == "" {
		missing = append(missing, "automation.shell")
	}
	if (result.Status == checks.StatusWarn || result.Status == checks.StatusFail) && len(result.RemediationSteps) == 0 {
		missing = append(missing, "remediation_steps")
	}
	if len(missing) > 0 {
		t.Fatalf("%s missing fields: %s", result.ID, strings.Join(missing, ", "))
	}
}

const dockerVersionJSON = `{
  "Client": {"Version": "25.0.3"},
  "Server": {"Version": "25.0.3"}
}`

const dockerInspectJSON = `[
  {
    "Id": "abc1234567890000000000000000000000000000000000000000000000000000",
    "Name": "/privileged-app",
    "Config": {
      "Image": "alpine:latest",
      "User": ""
    },
    "HostConfig": {
      "Privileged": true,
      "NetworkMode": "host",
      "CapAdd": ["NET_ADMIN", "CAP_SYS_ADMIN"],
      "SecurityOpt": [],
      "RestartPolicy": {"Name": "no"}
    },
    "Mounts": [
      {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
      {"Type": "bind", "Source": "/etc", "Destination": "/host_etc"}
    ]
  },
  {
    "Id": "safe9876543210000000000000000000000000000000000000000000000000000",
    "Name": "/safe-app",
    "Config": {
      "Image": "registry.example.com/app:1.2.3",
      "User": "1000"
    },
    "HostConfig": {
      "Privileged": false,
      "NetworkMode": "bridge",
      "CapAdd": ["CHOWN"],
      "SecurityOpt": ["no-new-privileges"],
      "RestartPolicy": {"Name": "unless-stopped"}
    },
    "Mounts": []
  }
]`
