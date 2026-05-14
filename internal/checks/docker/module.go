package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"secscan/internal/checks"
)

const (
	moduleID = "docker"
	service  = "docker"

	bytesGiB = 1024 * 1024 * 1024
)

var (
	dockerSocketPath       = "/var/run/docker.sock"
	dockerDataPath         = "/var/lib/docker"
	dockerOverlay2Path     = "/var/lib/docker/overlay2"
	dockerContainersPath   = "/var/lib/docker/containers"
	dockerDaemonConfigPath = "/etc/docker/daemon.json"
	dockerBinaryPaths      = []string{"/usr/bin/docker", "/usr/local/bin/docker", "/bin/docker"}
	dockerSocketPaths      = []string{"/var/run/docker.sock", "/run/docker.sock"}
	ownerGroupLookup       = ownerGroup
	lookPath               = exec.LookPath
)

type Module struct{}

type containerCache struct {
	loaded     bool
	containers []containerInspect
	err        error
}

func NewModule() Module {
	return Module{}
}

func (m Module) ID() string {
	return moduleID
}

func (m Module) Name() string {
	return "Docker"
}

func (m Module) Detect(ctx checks.Context) bool {
	detected, _ := detect(ctx)
	return detected
}

func (m Module) Checks() []checks.Check {
	cache := &containerCache{}
	return []checks.Check{
		checkDaemonDetected{},
		checkVersion{},
		checkSocketPermissions{},
		checkExposedTCPSocket{},
		checkPrivilegedContainers{cache: cache},
		checkHostMounts{cache: cache},
		checkHostNetwork{cache: cache},
		checkDangerousCapabilities{cache: cache},
		checkNoNewPrivileges{cache: cache},
		checkContainerUserRoot{cache: cache},
		checkImageTagLatest{cache: cache},
		checkRestartPolicy{cache: cache},
		checkUnusedData{},
		checkContainerLogsLarge{},
		checkOverlay2Usage{},
	}
}

type checkDaemonDetected struct{}

func (c checkDaemonDetected) ID() string {
	return "docker.daemon_detected"
}

func (c checkDaemonDetected) Title() string {
	return "Docker daemon detected"
}

func (c checkDaemonDetected) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Docker was detected on the host."
	result.ClientSummary = "Docker is present on the server."
	result.AdminDetails = "Checked running docker.service, Docker socket, Docker binary, and Docker data directory."
	result.Impact = "Inventory signal only; this does not indicate a security problem by itself."
	result.Recommendation = "Run Docker security baseline checks for daemon exposure, socket permissions, container privileges, and storage hygiene."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "systemctl is-active docker.service; test -S /var/run/docker.sock; command -v docker; test -d /var/lib/docker"}
	result.HiddenInClientReport = true

	detected, evidence := detect(ctx)
	result.Evidence = evidence
	if detected {
		return result
	}

	result.Status = checks.StatusNotApplicable
	result.Summary = "Docker was not detected on the host."
	result.ClientSummary = "Docker was not detected."
	result.AdminDetails = "No running docker.service, Docker socket, Docker binary, or Docker data directory was found."
	return result
}

type checkVersion struct{}

func (c checkVersion) ID() string {
	return "docker.version"
}

func (c checkVersion) Title() string {
	return "Docker version"
}

func (c checkVersion) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityInfo, checks.StatusInfo)
	result.Summary = "Docker client and server versions were collected."
	result.ClientSummary = "Docker version information was recorded."
	result.AdminDetails = "Executed docker version --format '{{json .}}' to collect client and server version metadata."
	result.Impact = "Docker version inventory helps prioritize patching and identify unsupported engine releases."
	result.Recommendation = "Keep Docker Engine and the Docker CLI supported and patched through the host package manager."
	result.Remediation = result.Recommendation
	result.Automation = checks.Automation{Shell: "docker version --format '{{json .}}'"}
	result.HiddenInClientReport = true

	if !ensureDockerDetected(ctx, &result, "Docker version check") {
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "docker", "version", "--format", "{{json .}}")
	if err != nil {
		return dockerCommandError(result, "docker version --format '{{json .}}'", err, checks.CategorySystem)
	}

	version, err := parseDockerVersion(output)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker version output could not be parsed."
		result.ClientSummary = "Docker version information could not be verified."
		result.Evidence = "docker_version=parse_error"
		result.AdminDetails = "Command returned invalid JSON: docker version --format '{{json .}}'\n" + err.Error()
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	result.Evidence = version.evidence()
	return result
}

type checkSocketPermissions struct{}

func (c checkSocketPermissions) ID() string {
	return "docker.socket_permissions"
}

func (c checkSocketPermissions) Title() string {
	return "Docker socket permissions"
}

func (c checkSocketPermissions) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityLow, checks.StatusPass)
	result.Summary = "Docker socket permissions match the standard local Docker Engine configuration."
	result.ClientSummary = "Docker socket permissions look standard."
	result.AdminDetails = "Inspected Docker socket mode, owner, group, socket type, path, and public TCP listeners."
	result.Impact = "Write access to the Docker socket is effectively root-level control of the host."
	result.Recommendation = "Restrict Docker socket write access to trusted administrators and avoid broad group membership."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review ownership and mode of /var/run/docker.sock.",
		"Remove world-writable permissions from the socket.",
		"Limit membership in the docker group to trusted administrators.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/security/protect-access/",
		"https://docs.docker.com/engine/install/linux-postinstall/",
	}
	result.Automation = checks.Automation{Shell: "stat -c '%a %U %G %n' /var/run/docker.sock; ss -lntp | grep -E 'dockerd|:2375|:2376' || true"}

	info, err := os.Stat(dockerSocketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result.Status = checks.StatusNotApplicable
			result.Severity = checks.SeverityInfo
			result.Summary = "Docker socket was not found."
			result.ClientSummary = "Docker socket was not found."
			result.AdminDetails = "The Docker socket path does not exist on this host."
			result.Evidence = "socket=not_found path=" + dockerSocketPath
			result.HiddenInClientReport = true
			return result
		}
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker socket permissions could not be read."
		result.ClientSummary = "Docker socket permissions could not be verified."
		result.AdminDetails = "Stat failed for " + dockerSocketPath + "\n" + err.Error()
		result.Evidence = "socket=stat_error path=" + dockerSocketPath
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	mode := info.Mode()
	owner, group := ownerGroupLookup(info)
	tcpListeners, tcpEvidence := ssDockerAPIListeners(ctx)
	result.Evidence = socketEvidence(info, owner, group) + "; " + tcpListenerEvidence(tcpListeners, tcpEvidence)
	publicAPI := publicDockerAPIListeners(tcpListeners)
	switch {
	case len(publicAPI) > 0:
		result.Title = "Docker API is exposed on a public TCP listener"
		result.Status = checks.StatusFail
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker API appears to listen on a public TCP endpoint."
		result.ClientSummary = "Docker remote API exposure is a high-risk finding."
		result.Evidence = socketEvidence(info, owner, group) + "; " + tcpListenerEvidence(publicAPI, tcpEvidence)
	case mode.Perm()&0002 != 0:
		result.Title = "Docker socket is world-writable"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker socket is writable by all local users."
		result.ClientSummary = "Docker socket permissions are unsafe."
	case !isRootOwner(owner):
		result.Title = "Docker socket owner is not root"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker socket is not owned by root."
		result.ClientSummary = "Docker socket ownership should be reviewed."
	case mode&os.ModeSocket == 0:
		result.Title = "Docker socket path is not a Unix socket"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker socket path exists but is not a Unix socket."
		result.ClientSummary = "Docker socket path should be reviewed."
	case !isExpectedSocketPath(dockerSocketPath):
		result.Title = "Docker socket is outside expected paths"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker socket path is outside the standard Docker Engine paths."
		result.ClientSummary = "Docker socket location should be reviewed."
	case mode.Perm() == 0660 && isDockerGroup(group):
		result.Title = "Docker socket uses standard root:docker permissions"
		result.Summary = "Docker socket is owned by root:docker with mode 0660 and no public TCP API listener was detected."
		result.ClientSummary = "Docker socket permissions match the standard Docker Engine configuration."
		result.AdminDetails += "\nMembers of docker group effectively have root-equivalent access."
	case mode.Perm() == 0600:
		result.Title = "Docker socket is root-only"
		result.Summary = "Docker socket mode is 0600 and no public TCP API listener was detected."
		result.ClientSummary = "Docker socket is restricted to the owner."
	case mode.Perm()&0020 != 0 && isDockerGroup(group):
		result.Title = "Docker socket is writable by the docker group"
		result.Status = checks.StatusInfo
		result.Severity = checks.SeverityLow
		result.Summary = "Docker socket is writable by the docker group."
		result.ClientSummary = "Docker socket docker-group access should be limited to trusted administrators."
		result.AdminDetails += "\nMembers of docker group effectively have root-equivalent access."
	case mode.Perm()&0020 != 0:
		result.Title = "Docker socket is group-writable"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker socket is writable by its owning group."
		result.ClientSummary = "Docker socket group write access should be reviewed."
	default:
		result.Title = "Docker socket is not broadly writable"
	}
	return result
}

type checkExposedTCPSocket struct{}

func (c checkExposedTCPSocket) ID() string {
	return "docker.exposed_tcp_socket"
}

func (c checkExposedTCPSocket) Title() string {
	return "Docker TCP API exposure"
}

func (c checkExposedTCPSocket) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityHigh, checks.StatusPass)
	result.Summary = "No Docker TCP API endpoint was detected."
	result.ClientSummary = "Docker TCP API exposure was not detected."
	result.AdminDetails = "Checked ss -tulpn, /etc/docker/daemon.json, and docker.service ExecStart for tcp:// Docker daemon endpoints."
	result.Impact = "An exposed Docker API can allow container creation, host filesystem access, and full host compromise."
	result.Recommendation = "Do not expose the Docker API over unauthenticated TCP; prefer the local Unix socket or a TLS-protected remote API restricted by firewall policy."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review dockerd -H options and /etc/docker/daemon.json hosts entries.",
		"Remove unauthenticated tcp://0.0.0.0:2375 listeners.",
		"Use TLS verification and network restrictions for any required remote Docker API.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/security/protect-access/",
		"https://docs.docker.com/reference/cli/dockerd/",
	}
	result.Automation = checks.Automation{Shell: "ss -tulpn | grep -E 'dockerd|:2375|:2376' || true; systemctl show docker.service -p ExecStart --value; cat /etc/docker/daemon.json"}

	if !ensureDockerDetected(ctx, &result, "Docker TCP API exposure check") {
		return result
	}

	endpoints, sourceEvidence := dockerTCPEndpoints(ctx)
	result.Evidence = joinEvidence(append(endpointEvidence(endpoints), sourceEvidence...), 10)
	if len(endpoints) == 0 {
		result.Evidence = joinEvidence(append([]string{"tcp_api=not_detected"}, sourceEvidence...), 10)
		return result
	}

	publicAPI := publicDockerAPIListeners(endpoints)
	if len(publicAPI) > 0 {
		result.Title = "Docker API is exposed on a public TCP listener"
		result.Status = checks.StatusFail
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker API appears to listen on a public TCP endpoint."
		result.ClientSummary = "Docker remote API exposure is a high-risk finding."
		result.Evidence = joinEvidence(endpointEvidence(publicAPI), 10)
		return result
	}

	localhost := filterEndpoints(endpoints, func(endpoint tcpEndpoint) bool {
		return isLoopbackHost(endpoint.Host)
	})
	if len(localhost) > 0 {
		result.Title = "Docker TCP API listens on localhost"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker API appears to listen on a localhost TCP endpoint."
		result.ClientSummary = "Docker TCP API is bound to localhost and should be reviewed."
		result.Evidence = joinEvidence(endpointEvidence(localhost), 10)
		return result
	}

	result.Title = "Docker TCP API endpoint needs review"
	result.Status = checks.StatusWarn
	result.Severity = checks.SeverityMedium
	result.Summary = "Docker API TCP configuration was detected and should be reviewed."
	result.ClientSummary = "Docker TCP API configuration should be reviewed."
	return result
}

type checkPrivilegedContainers struct {
	cache *containerCache
}

func (c checkPrivilegedContainers) ID() string {
	return "docker.privileged_containers"
}

func (c checkPrivilegedContainers) Title() string {
	return "Privileged containers"
}

func (c checkPrivilegedContainers) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "No running privileged containers were detected."
	result.ClientSummary = "No running privileged containers were detected."
	result.AdminDetails = "Inspected running containers for HostConfig.Privileged=true."
	result.Impact = "Privileged containers bypass most container isolation and can directly affect the host."
	result.Recommendation = "Avoid privileged containers; grant only the specific devices, capabilities, and mounts required by the workload."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify containers running with Privileged=true.",
		"Replace --privileged with narrowly scoped capabilities, devices, or mounts.",
		"Redeploy the container and verify the application still works with reduced privileges.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker ps --format '{{.ID}} {{.Image}} {{.Names}}'; docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "privileged container check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		if container.HostConfig.Privileged {
			findings = append(findings, fmt.Sprintf("%s image=%s", containerIdentity(container), container.Config.Image))
		}
	}

	result.Evidence = evidenceOrNone(findings, "privileged_containers=none")
	if len(findings) > 0 {
		result.Title = "Privileged containers are running"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d privileged container(s) are running.", len(findings))
		result.ClientSummary = "Some containers are running with full host-level privileges."
		result.Evidence = joinEvidence(findings, 10)
	}
	return result
}

type checkHostMounts struct {
	cache *containerCache
}

func (c checkHostMounts) ID() string {
	return "docker.host_mounts"
}

func (c checkHostMounts) Title() string {
	return "Critical host bind mounts"
}

func (c checkHostMounts) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "No critical host bind mounts were detected in running containers."
	result.ClientSummary = "No critical host bind mounts were detected."
	result.AdminDetails = "Inspected running container Mounts entries for critical host paths."
	result.Impact = "Critical host mounts can expose host secrets, kernel interfaces, or Docker control paths inside containers."
	result.Recommendation = "Remove critical host bind mounts unless they are strictly required, and prefer read-only, narrowly scoped paths."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review containers with critical bind mounts.",
		"Replace broad host mounts with narrow read-only paths where possible.",
		"Remove Docker socket and host root mounts from containers unless explicitly required and risk-accepted.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/storage/bind-mounts/",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{json .Mounts}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "host mount check")
	if !ok {
		return result
	}

	findings := []mountFinding{}
	for _, container := range containers {
		for _, mount := range container.Mounts {
			if !strings.EqualFold(mount.Type, "bind") {
				continue
			}
			if severity, matched, ok := criticalMountSeverity(mount.Source); ok {
				findings = append(findings, mountFinding{
					Container: containerIdentity(container),
					Source:    mount.Source,
					Target:    mount.Destination,
					Matched:   matched,
					Severity:  severity,
				})
			}
		}
	}

	if len(findings) == 0 {
		result.Evidence = "critical_host_mounts=none"
		return result
	}

	result.Title = "Critical host paths are mounted into containers"
	result.Status = checks.StatusWarn
	result.Severity = highestMountSeverity(findings)
	result.Summary = fmt.Sprintf("%d critical host bind mount(s) were detected.", len(findings))
	result.ClientSummary = "Some containers mount sensitive host paths."
	result.Evidence = joinEvidence(mountEvidence(findings), 10)
	return result
}

type checkHostNetwork struct {
	cache *containerCache
}

func (c checkHostNetwork) ID() string {
	return "docker.host_network"
}

func (c checkHostNetwork) Title() string {
	return "Host network mode"
}

func (c checkHostNetwork) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "No running containers use host network mode."
	result.ClientSummary = "No running containers use host network mode."
	result.AdminDetails = "Inspected HostConfig.NetworkMode for running containers."
	result.Impact = "Host network mode removes Docker network isolation and can expose host services or packet capture capability to the container."
	result.Recommendation = "Use bridge or application-specific Docker networks unless host networking is strictly required."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify containers using NetworkMode=host.",
		"Move the workload to a bridge or dedicated Docker network where possible.",
		"Document and restrict any workload that must retain host networking.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/network/drivers/host/",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{.Config.Image}} {{.HostConfig.NetworkMode}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "host network check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		if strings.EqualFold(container.HostConfig.NetworkMode, "host") {
			findings = append(findings, fmt.Sprintf("%s image=%s", containerIdentity(container), container.Config.Image))
		}
	}
	result.Evidence = evidenceOrNone(findings, "host_network=none")
	if len(findings) > 0 {
		result.Title = "Containers use host network mode"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d container(s) use host network mode.", len(findings))
		result.ClientSummary = "Some containers share the host network namespace."
		result.Evidence = joinEvidence(findings, 10)
	}
	return result
}

type checkDangerousCapabilities struct {
	cache *containerCache
}

func (c checkDangerousCapabilities) ID() string {
	return "docker.dangerous_capabilities"
}

func (c checkDangerousCapabilities) Title() string {
	return "Dangerous Linux capabilities"
}

func (c checkDangerousCapabilities) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityHigh, checks.StatusPass)
	result.Summary = "No dangerous added Linux capabilities were detected."
	result.ClientSummary = "No dangerous added Linux capabilities were detected."
	result.AdminDetails = "Inspected HostConfig.CapAdd for dangerous Linux capabilities."
	result.Impact = "Powerful capabilities such as SYS_ADMIN or SYS_MODULE can weaken container isolation or expose host kernel attack paths."
	result.Recommendation = "Drop dangerous capabilities and add only narrowly required Linux capabilities per workload."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review containers with added dangerous capabilities.",
		"Remove SYS_ADMIN, NET_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, and SYS_MODULE unless explicitly required.",
		"Redeploy with least-privilege capability settings and verify workload behavior.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
		"https://man7.org/linux/man-pages/man7/capabilities.7.html",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{json .HostConfig.CapAdd}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "dangerous capabilities check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		caps := dangerousCapabilities(container.HostConfig.CapAdd)
		if len(caps) == 0 {
			continue
		}
		findings = append(findings, fmt.Sprintf("%s caps=%s", containerIdentity(container), strings.Join(caps, ",")))
	}
	result.Evidence = evidenceOrNone(findings, "dangerous_capabilities=none")
	if len(findings) > 0 {
		result.Title = "Containers have dangerous Linux capabilities"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d container(s) have dangerous Linux capabilities.", len(findings))
		result.ClientSummary = "Some containers have powerful Linux capabilities enabled."
		result.Evidence = joinEvidence(findings, 10)
	}
	return result
}

type checkNoNewPrivileges struct {
	cache *containerCache
}

func (c checkNoNewPrivileges) ID() string {
	return "docker.no_new_privileges"
}

func (c checkNoNewPrivileges) Title() string {
	return "no-new-privileges security option"
}

func (c checkNoNewPrivileges) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Running containers use no-new-privileges."
	result.ClientSummary = "Running containers use no-new-privileges."
	result.AdminDetails = "Inspected HostConfig.SecurityOpt for no-new-privileges."
	result.Impact = "Without no-new-privileges, a process may gain additional privileges through setuid binaries or file capabilities inside the container."
	result.Recommendation = "Run containers with --security-opt no-new-privileges where compatible with the application."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify containers missing no-new-privileges.",
		"Add --security-opt no-new-privileges to compatible workloads.",
		"Redeploy and verify that the workload does not require privilege escalation.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/containers/run/#security-configuration",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{json .HostConfig.SecurityOpt}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "no-new-privileges check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		if !hasNoNewPrivileges(container.HostConfig.SecurityOpt) {
			findings = append(findings, containerIdentity(container))
		}
	}
	result.Evidence = evidenceWithCount(findings, "affected_count")
	if len(findings) > 0 {
		result.Title = "Containers are missing no-new-privileges"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d container(s) do not use no-new-privileges.", len(findings))
		result.ClientSummary = "Some containers allow privilege escalation paths."
		result.Evidence = evidenceWithCountAndList(findings, "affected_count")
	}
	return result
}

type checkContainerUserRoot struct {
	cache *containerCache
}

func (c checkContainerUserRoot) ID() string {
	return "docker.container_user_root"
}

func (c checkContainerUserRoot) Title() string {
	return "Container user is non-root"
}

func (c checkContainerUserRoot) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityMedium, checks.StatusPass)
	result.Summary = "No running containers explicitly run as root or with an empty user setting."
	result.ClientSummary = "Running containers do not appear to run as root."
	result.AdminDetails = "Inspected Config.User for running containers."
	result.Impact = "Containers running as root increase the impact of container escapes, writable mounts, and application compromise."
	result.Recommendation = "Run application containers as a dedicated non-root user whenever possible."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify containers with Config.User empty, root, or UID 0.",
		"Update Dockerfiles or runtime options to use a dedicated non-root user.",
		"Redeploy and verify file permissions required by the application.",
	}
	result.References = []string{
		"https://docs.docker.com/reference/dockerfile/#user",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{.Config.Image}} user={{.Config.User}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "container user check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		if containerRunsAsRoot(container.Config.User) {
			userValue := strings.TrimSpace(container.Config.User)
			if userValue == "" {
				userValue = "empty"
			}
			findings = append(findings, fmt.Sprintf("%s image=%s user=%s", containerIdentity(container), container.Config.Image, userValue))
		}
	}
	result.Evidence = evidenceWithCount(findings, "affected_count")
	if len(findings) > 0 {
		result.Title = "Containers run as root"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d container(s) run as root or have an empty user setting.", len(findings))
		result.ClientSummary = "Some containers run as root."
		result.Evidence = evidenceWithCountAndList(findings, "affected_count")
	}
	return result
}

type checkImageTagLatest struct {
	cache *containerCache
}

func (c checkImageTagLatest) ID() string {
	return "docker.image_tag_latest"
}

func (c checkImageTagLatest) Title() string {
	return "Container images avoid latest tag"
}

func (c checkImageTagLatest) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusPass)
	result.Summary = "No running container image uses the latest tag."
	result.ClientSummary = "Running container images do not use the latest tag."
	result.AdminDetails = "Inspected Config.Image for running containers."
	result.Impact = "The latest tag is mutable and can make deployments less reproducible or unexpectedly change the runtime image."
	result.Recommendation = "Pin images to explicit immutable versions or digests."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify running containers using the latest tag.",
		"Choose explicit version tags or immutable image digests.",
		"Redeploy workloads with pinned images through the normal deployment process.",
	}
	result.References = []string{
		"https://docs.docker.com/reference/cli/docker/image/tag/",
		"https://www.cisecurity.org/benchmark/docker",
	}
	result.Automation = checks.Automation{Shell: "docker ps --format '{{.ID}} {{.Image}} {{.Names}}'"}

	containers, ok := containersForResult(ctx, c.cache, &result, "image tag check")
	if !ok {
		return result
	}

	findings := []string{}
	seen := map[string]struct{}{}
	for _, container := range containers {
		if !imageUsesLatest(container.Config.Image) {
			continue
		}
		evidence := fmt.Sprintf("image=%s container=%s", container.Config.Image, containerIdentity(container))
		if _, ok := seen[evidence]; ok {
			continue
		}
		seen[evidence] = struct{}{}
		findings = append(findings, evidence)
	}
	result.Evidence = evidenceOrNone(findings, "latest_images=none")
	if len(findings) > 0 {
		result.Title = "Container images use the latest tag"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d running container image reference(s) use the latest tag.", len(findings))
		result.ClientSummary = "Some running container images use the mutable latest tag."
		result.Evidence = joinEvidence(findings, 10)
	}
	return result
}

type checkRestartPolicy struct {
	cache *containerCache
}

func (c checkRestartPolicy) ID() string {
	return "docker.restart_policy"
}

func (c checkRestartPolicy) Title() string {
	return "Container restart policy"
}

func (c checkRestartPolicy) Run(ctx checks.Context) checks.Result {
	result := newContainerResult(c.ID(), c.Title(), checks.SeverityLow, checks.StatusInfo)
	result.Summary = "Running containers have restart policies configured."
	result.ClientSummary = "Running containers have restart policies configured."
	result.AdminDetails = "Inspected HostConfig.RestartPolicy for running containers."
	result.Impact = "Containers without restart policies may remain down after daemon restarts or host maintenance."
	result.Recommendation = "Configure an intentional restart policy for long-running service containers."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify service containers without restart policies.",
		"Select an appropriate policy such as unless-stopped or on-failure.",
		"Apply the policy through the normal deployment definition.",
	}
	result.References = []string{
		"https://docs.docker.com/engine/containers/start-containers-automatically/",
	}
	result.Automation = checks.Automation{Shell: "docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(docker ps -q)"}

	containers, ok := containersForResult(ctx, c.cache, &result, "restart policy check")
	if !ok {
		return result
	}

	findings := []string{}
	for _, container := range containers {
		if noRestartPolicy(container.HostConfig.RestartPolicy.Name) {
			findings = append(findings, fmt.Sprintf("%s image=%s restart_policy=none", containerIdentity(container), container.Config.Image))
		}
	}
	result.Evidence = evidenceOrNone(findings, "containers_without_restart_policy=none")
	if len(findings) > 0 {
		result.Title = "Containers lack restart policies"
		result.Status = checks.StatusWarn
		result.Summary = fmt.Sprintf("%d container(s) do not have a restart policy.", len(findings))
		result.ClientSummary = "Some service containers may not restart automatically."
		result.Evidence = joinEvidence(findings, 10)
	}
	return result
}

type checkUnusedData struct{}

func (c checkUnusedData) ID() string {
	return "docker.unused_data"
}

func (c checkUnusedData) Title() string {
	return "Docker unused data"
}

func (c checkUnusedData) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityLow, checks.StatusInfo)
	result.Summary = "Docker reclaimable data was inventoried."
	result.ClientSummary = "Docker reclaimable data was checked."
	result.AdminDetails = "Executed docker system df and parsed reclaimable size by data type."
	result.Impact = "Large reclaimable Docker data can consume disk space and cause service instability during writes or image pulls."
	result.Recommendation = "Review Docker disk usage and remove unused images, containers, volumes, or build cache only through an approved maintenance process."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review docker system df output and identify reclaimable data types.",
		"Confirm unused data with workload owners before deleting anything.",
		"Schedule cleanup through the normal maintenance process if space pressure exists.",
	}
	result.Automation = checks.Automation{Shell: "docker system df"}

	if !ensureDockerDetected(ctx, &result, "Docker unused data check") {
		return result
	}

	output, err := ctx.Runner.Run(ctx.Context, "docker", "system", "df")
	if err != nil {
		return dockerCommandError(result, "docker system df", err, checks.CategorySystem)
	}

	usage := parseSystemDF(string(output))
	if len(usage.Rows) == 0 {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker disk usage output could not be parsed."
		result.ClientSummary = "Docker reclaimable data could not be verified."
		result.AdminDetails = "docker system df returned no parseable rows."
		result.Evidence = "docker_system_df=parse_error"
		result.Error = "no parseable docker system df rows"
		result.HiddenInClientReport = true
		return result
	}

	result.Evidence = usage.evidence()
	if usage.TotalReclaimable > 20*bytesGiB {
		result.Title = "Docker has large reclaimable data"
		result.Status = checks.StatusWarn
		result.Summary = "Docker reports more than 20 GiB of reclaimable data."
		result.ClientSummary = "Docker has a large amount of reclaimable disk usage."
	}
	return result
}

type checkContainerLogsLarge struct{}

func (c checkContainerLogsLarge) ID() string {
	return "docker.container_logs_large"
}

func (c checkContainerLogsLarge) Title() string {
	return "Large Docker JSON logs"
}

func (c checkContainerLogsLarge) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityMedium, checks.StatusPass)
	result.Summary = "No Docker JSON log over 1 GiB was detected."
	result.ClientSummary = "Docker container logs do not appear oversized."
	result.AdminDetails = "Checked /var/lib/docker/containers/*/*-json.log file sizes."
	result.Impact = "Oversized container logs can fill disks and disrupt Docker or application workloads."
	result.Recommendation = "Configure Docker log rotation and review noisy containers before truncating or removing logs through approved maintenance."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Identify containers with JSON logs over 1 GiB.",
		"Configure Docker log rotation through daemon or service deployment settings.",
		"Review application logging volume before performing any approved log cleanup.",
	}
	result.References = []string{
		"https://docs.docker.com/config/containers/logging/json-file/",
	}
	result.Automation = checks.Automation{Shell: "find /var/lib/docker/containers -name '*-json.log' -type f -printf '%s %p\\n' 2>/dev/null | sort -nr | head"}

	if !ensureReadablePath(&result, dockerDataPath, "docker_data_path", "Docker data directory was not found; log size check was skipped.") {
		return result
	}
	if !ensureReadablePath(&result, dockerContainersPath, "docker_containers_path", "Docker containers directory was not found; log size check was skipped.") {
		return result
	}

	logs, err := largeJSONLogs(dockerContainersPath, bytesGiB)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker container logs could not be read."
		result.ClientSummary = "Docker container logs could not be verified."
		result.AdminDetails = "Walking Docker containers log directory failed.\n" + err.Error()
		result.Evidence = "container_logs=read_error path=" + dockerContainersPath
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	if len(logs) == 0 {
		result.Evidence = "large_json_logs=none threshold=1GiB"
		return result
	}

	result.Title = "Large Docker JSON logs were found"
	result.Status = checks.StatusWarn
	result.Summary = fmt.Sprintf("%d Docker JSON log file(s) exceed 1 GiB.", len(logs))
	result.ClientSummary = "Some Docker container logs are very large."
	result.Evidence = joinEvidence(logFileEvidence(logs), 10)
	return result
}

type checkOverlay2Usage struct{}

func (c checkOverlay2Usage) ID() string {
	return "docker.overlay2_usage"
}

func (c checkOverlay2Usage) Title() string {
	return "Docker overlay2 usage"
}

func (c checkOverlay2Usage) Run(ctx checks.Context) checks.Result {
	result := newResult(c.ID(), c.Title(), checks.CategorySystem, checks.SeverityMedium, checks.StatusPass)
	result.Summary = "Docker overlay2 usage is below the warning threshold."
	result.ClientSummary = "Docker overlay2 storage usage is within the expected range."
	result.AdminDetails = "Calculated total size under /var/lib/docker/overlay2."
	result.Impact = "Large overlay2 usage can consume host disk space and affect image pulls, container writes, or system stability."
	result.Recommendation = "Review Docker storage usage and remove unused data only through an approved maintenance process."
	result.Remediation = result.Recommendation
	result.RemediationSteps = []string{
		"Review Docker overlay2 size and docker system df output.",
		"Identify unused images or stopped containers before any cleanup.",
		"Schedule approved cleanup or storage expansion if Docker data usage is high.",
	}
	result.Automation = checks.Automation{Shell: "du -sh /var/lib/docker/overlay2 2>/dev/null"}

	if !ensureReadablePath(&result, dockerDataPath, "docker_data_path", "Docker data directory was not found; overlay2 check was skipped.") {
		return result
	}
	if !ensureReadablePath(&result, dockerOverlay2Path, "overlay2_path", "Docker overlay2 directory was not found.") {
		return result
	}

	size, err := directorySize(dockerOverlay2Path)
	if err != nil {
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = "Docker overlay2 usage could not be calculated."
		result.ClientSummary = "Docker overlay2 usage could not be verified."
		result.AdminDetails = "Walking overlay2 directory failed.\n" + err.Error()
		result.Evidence = "overlay2=read_error path=" + dockerOverlay2Path
		result.Error = err.Error()
		result.HiddenInClientReport = true
		return result
	}

	result.Evidence = "overlay2_size=" + humanBytes(size) + " path=" + dockerOverlay2Path
	switch {
	case size > 80*bytesGiB:
		result.Title = "Docker overlay2 usage is very high"
		result.Status = checks.StatusWarn
		result.Severity = checks.SeverityHigh
		result.Summary = "Docker overlay2 usage exceeds 80 GiB."
		result.ClientSummary = "Docker overlay2 storage usage is very high."
	case size > 30*bytesGiB:
		result.Title = "Docker overlay2 usage is high"
		result.Status = checks.StatusWarn
		result.Summary = "Docker overlay2 usage exceeds 30 GiB."
		result.ClientSummary = "Docker overlay2 storage usage is high."
	}
	return result
}

func newResult(id, title string, category checks.Category, severity checks.Severity, status checks.Status) checks.Result {
	result := checks.NewResult(id, moduleID, service, title, severity, status)
	result.Category = category
	return result
}

func newContainerResult(id, title string, severity checks.Severity, status checks.Status) checks.Result {
	return newResult(id, title, checks.CategoryCompliance, severity, status)
}

func detect(ctx checks.Context) (bool, string) {
	if !linuxTarget(ctx) {
		return false, "detected=false goos=" + ctx.Host.GOOS
	}

	for _, svc := range ctx.Services {
		if strings.EqualFold(svc.Unit, "docker.service") {
			return true, "service=docker.service"
		}
	}

	if _, err := os.Stat(dockerSocketPath); err == nil {
		return true, "socket=" + dockerSocketPath
	}
	if path, ok := firstExistingPath(dockerBinaryPaths); ok {
		return true, "binary=" + path
	}
	if lookPath != nil {
		if path, err := lookPath("docker"); err == nil && path != "" {
			return true, "binary=" + path
		}
	}
	if info, err := os.Stat(dockerDataPath); err == nil && info.IsDir() {
		return true, "path=" + dockerDataPath
	}

	return false, "detected=false"
}

func linuxTarget(ctx checks.Context) bool {
	if ctx.Host.GOOS == "" {
		return true
	}
	return ctx.Host.GOOS == "linux" || len(ctx.Host.OSRelease) > 0
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
}

func ensureDockerDetected(ctx checks.Context, result *checks.Result, checkName string) bool {
	detected, evidence := detect(ctx)
	if detected {
		return true
	}

	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = "Docker was not detected; " + checkName + " was skipped."
	result.ClientSummary = "Docker was not detected."
	result.AdminDetails = "This check requires Docker to be installed or running."
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return false
}

func notApplicable(result checks.Result, evidence, summary string) checks.Result {
	result.Status = checks.StatusNotApplicable
	result.Severity = checks.SeverityInfo
	result.Summary = summary
	result.ClientSummary = summary
	result.Evidence = evidence
	result.HiddenInClientReport = true
	return result
}

func dockerCommandError(result checks.Result, command string, err error, category checks.Category) checks.Result {
	result.Category = category
	result.Status = checks.StatusError
	result.Severity = checks.SeverityMedium
	result.Summary = "Docker command could not be executed."
	result.ClientSummary = "Docker security checks could not query Docker."
	result.AdminDetails = "Command failed: " + command + "\n" + err.Error()
	result.Evidence = dockerErrorEvidence(command, err)
	result.Error = err.Error()
	result.HiddenInClientReport = true
	return result
}

func dockerErrorEvidence(command string, err error) string {
	message := compactWhitespace(err.Error())
	lower := strings.ToLower(message)
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "permission_denied") {
		return "docker_api=permission_denied command=" + command + " error=" + message
	}
	if strings.Contains(lower, "cannot connect to the docker daemon") {
		return "docker_api=unavailable command=" + command + " error=" + message
	}
	return "docker_command=failed command=" + command + " error=" + message
}

type dockerVersionInfo struct {
	ClientVersion string
	ServerVersion string
}

type dockerVersionPayload struct {
	Client struct {
		Version string `json:"Version"`
	} `json:"Client"`
	Server *struct {
		Version string `json:"Version"`
	} `json:"Server"`
}

func parseDockerVersion(data []byte) (dockerVersionInfo, error) {
	payload := dockerVersionPayload{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return dockerVersionInfo{}, err
	}

	info := dockerVersionInfo{
		ClientVersion: strings.TrimSpace(payload.Client.Version),
		ServerVersion: "unavailable",
	}
	if payload.Server != nil && strings.TrimSpace(payload.Server.Version) != "" {
		info.ServerVersion = strings.TrimSpace(payload.Server.Version)
	}
	if info.ClientVersion == "" {
		info.ClientVersion = "unknown"
	}
	return info, nil
}

func (i dockerVersionInfo) evidence() string {
	return "client_version=" + i.ClientVersion + "; server_version=" + i.ServerVersion
}

func socketEvidence(info fs.FileInfo, owner, group string) string {
	mode := info.Mode()
	return fmt.Sprintf("mode=%04o owner=%s group=%s path=%s", mode.Perm(), owner, group, dockerSocketPath)
}

func isRootOwner(owner string) bool {
	owner = strings.ToLower(strings.TrimSpace(owner))
	return owner == "root" || owner == "0" || strings.HasPrefix(owner, "root(")
}

func isDockerGroup(group string) bool {
	group = strings.ToLower(strings.TrimSpace(group))
	return group == "docker" || strings.HasPrefix(group, "docker(")
}

func isExpectedSocketPath(path string) bool {
	clean := filepath.Clean(path)
	for _, expected := range dockerSocketPaths {
		if clean == filepath.Clean(expected) {
			return true
		}
	}
	return false
}

func ssDockerAPIListeners(ctx checks.Context) ([]tcpEndpoint, string) {
	if ctx.Runner == nil {
		return nil, "tcp_listeners=unavailable"
	}
	output, err := ctx.Runner.Run(ctx.Context, "ss", "-lntp")
	if err != nil {
		return nil, "tcp_listeners=unavailable"
	}
	return parseSSTCPEndpoints(string(output)), "tcp_listeners=checked"
}

func publicDockerAPIListeners(endpoints []tcpEndpoint) []tcpEndpoint {
	return filterEndpoints(endpoints, func(endpoint tcpEndpoint) bool {
		return (endpoint.Port == "2375" || endpoint.Port == "2376") && !isLoopbackHost(endpoint.Host)
	})
}

func tcpListenerEvidence(endpoints []tcpEndpoint, fallback string) string {
	if len(endpoints) == 0 {
		if fallback == "" || fallback == "tcp_listeners=checked" {
			return "tcp_listeners=none"
		}
		return fallback
	}
	return "tcp_listeners=" + joinEvidence(endpointEvidence(endpoints), 10)
}

func ownerGroup(info fs.FileInfo) (string, string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown", "unknown"
	}

	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	owner := uid
	group := gid
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		owner = u.Username + "(" + uid + ")"
	}
	if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
		group = g.Name + "(" + gid + ")"
	}
	return owner, group
}

type tcpEndpoint struct {
	Endpoint string
	Host     string
	Port     string
	Source   string
}

func dockerTCPEndpoints(ctx checks.Context) ([]tcpEndpoint, []string) {
	endpoints := []tcpEndpoint{}
	evidence := []string{}

	ssEndpoints, ssEvidence := ssTCPEndpoints(ctx)
	endpoints = append(endpoints, ssEndpoints...)
	evidence = append(evidence, ssEvidence)

	configEndpoints, configEvidence := daemonConfigTCPEndpoints(dockerDaemonConfigPath)
	endpoints = append(endpoints, configEndpoints...)
	evidence = append(evidence, configEvidence)

	systemdEndpoints, systemdEvidence := systemdExecStartTCPEndpoints(ctx)
	endpoints = append(endpoints, systemdEndpoints...)
	evidence = append(evidence, systemdEvidence)

	return uniqueEndpoints(endpoints), evidence
}

func ssTCPEndpoints(ctx checks.Context) ([]tcpEndpoint, string) {
	output, err := ctx.Runner.Run(ctx.Context, "ss", "-tulpn")
	if err != nil {
		return nil, "ss=unavailable"
	}
	return parseSSTCPEndpoints(string(output)), "ss=checked"
}

func parseSSTCPEndpoints(output string) []tcpEndpoint {
	endpoints := []tcpEndpoint{}
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "docker") && !strings.Contains(line, ":2375") && !strings.Contains(line, ":2376") {
			continue
		}
		for _, field := range strings.Fields(line) {
			host, port, ok := splitHostPortLoose(field)
			if !ok {
				continue
			}
			if port != "2375" && port != "2376" && !strings.Contains(lower, "docker") {
				continue
			}
			endpoints = append(endpoints, tcpEndpoint{
				Endpoint: "tcp://" + host + ":" + port,
				Host:     host,
				Port:     port,
				Source:   "ss",
			})
		}
	}
	return endpoints
}

func daemonConfigTCPEndpoints(path string) ([]tcpEndpoint, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "daemon_json=not_found"
		}
		return nil, "daemon_json=read_error"
	}

	raw := map[string]interface{}{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, "daemon_json=parse_error"
	}

	hosts := hostsFromDaemonConfig(raw["hosts"])
	endpoints := []tcpEndpoint{}
	for _, host := range hosts {
		endpoint, ok := endpointFromDockerHost(host, "daemon.json")
		if ok {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, "daemon_json=checked"
}

func hostsFromDaemonConfig(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []interface{}:
		hosts := []string{}
		for _, item := range typed {
			if host, ok := item.(string); ok {
				hosts = append(hosts, host)
			}
		}
		return hosts
	default:
		return nil
	}
}

func systemdExecStartTCPEndpoints(ctx checks.Context) ([]tcpEndpoint, string) {
	output, err := ctx.Runner.Run(ctx.Context, "systemctl", "show", "docker.service", "-p", "ExecStart", "--value")
	if err != nil {
		return nil, "systemd_execstart=unavailable"
	}

	endpoints := []tcpEndpoint{}
	for _, token := range strings.Fields(string(output)) {
		if !strings.Contains(token, "tcp://") {
			continue
		}
		if endpoint, ok := endpointFromDockerHost(strings.Trim(token, `"',;`), "systemd_execstart"); ok {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, "systemd_execstart=checked"
}

func endpointFromDockerHost(value, source string) (tcpEndpoint, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "tcp://") {
		return tcpEndpoint{}, false
	}

	address := strings.TrimPrefix(value, "tcp://")
	host, port, ok := splitHostPortLoose(address)
	if !ok {
		return tcpEndpoint{}, false
	}
	return tcpEndpoint{
		Endpoint: "tcp://" + host + ":" + port,
		Host:     host,
		Port:     port,
		Source:   source,
	}, true
}

func splitHostPortLoose(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'(),;`)
	if value == "" {
		return "", "", false
	}

	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end > 0 {
			host := value[1:end]
			port := value[end+2:]
			if isPort(port) {
				return normalizeHost(host), port, true
			}
		}
	}

	if host, port, err := net.SplitHostPort(value); err == nil && isPort(port) {
		return normalizeHost(host), port, true
	}

	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return "", "", false
	}
	host := value[:idx]
	port := strings.TrimRight(value[idx+1:], ",;")
	if !isPort(port) {
		return "", "", false
	}
	return normalizeHost(host), port, true
}

func normalizeHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "0.0.0.0"
	}
	if zone := strings.LastIndex(host, "%"); zone > 0 {
		host = host[:zone]
	}
	if host == "*" {
		return "0.0.0.0"
	}
	return host
}

func isPort(port string) bool {
	if port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func uniqueEndpoints(endpoints []tcpEndpoint) []tcpEndpoint {
	seen := map[string]struct{}{}
	out := []tcpEndpoint{}
	for _, endpoint := range endpoints {
		key := endpoint.Endpoint + "|" + endpoint.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

func filterEndpoints(endpoints []tcpEndpoint, match func(tcpEndpoint) bool) []tcpEndpoint {
	out := []tcpEndpoint{}
	for _, endpoint := range endpoints {
		if match(endpoint) {
			out = append(out, endpoint)
		}
	}
	return out
}

func endpointEvidence(endpoints []tcpEndpoint) []string {
	evidence := []string{}
	for _, endpoint := range endpoints {
		evidence = append(evidence, "endpoint="+endpoint.Endpoint+" source="+endpoint.Source)
	}
	return evidence
}

type containerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
		User  string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged    bool     `json:"Privileged"`
		NetworkMode   string   `json:"NetworkMode"`
		CapAdd        []string `json:"CapAdd"`
		SecurityOpt   []string `json:"SecurityOpt"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []containerMount `json:"Mounts"`
}

type containerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

func (c *containerCache) load(ctx checks.Context) ([]containerInspect, error) {
	if c == nil {
		return loadContainers(ctx)
	}
	if !c.loaded {
		c.containers, c.err = loadContainers(ctx)
		c.loaded = true
	}
	return c.containers, c.err
}

func loadContainers(ctx checks.Context) ([]containerInspect, error) {
	output, err := ctx.Runner.Run(ctx.Context, "docker", "ps", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}

	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return []containerInspect{}, nil
	}

	args := append([]string{"inspect"}, ids...)
	output, err = ctx.Runner.Run(ctx.Context, "docker", args...)
	if err != nil {
		return nil, err
	}

	containers := []containerInspect{}
	if err := json.Unmarshal(output, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

func containersForResult(ctx checks.Context, cache *containerCache, result *checks.Result, checkName string) ([]containerInspect, bool) {
	if !ensureDockerDetected(ctx, result, checkName) {
		return nil, false
	}

	containers, err := cache.load(ctx)
	if err != nil {
		*result = dockerCommandError(*result, "docker ps / docker inspect", err, result.Category)
		return nil, false
	}

	if len(containers) == 0 {
		result.Evidence = "containers=none"
		return containers, true
	}
	return containers, true
}

func containerIdentity(container containerInspect) string {
	name := strings.TrimPrefix(strings.TrimSpace(container.Name), "/")
	id := shortID(container.ID)
	if name == "" {
		name = "unknown"
	}
	if id == "" {
		return "name=" + name
	}
	return "name=" + name + " id=" + id
}

func shortID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

type mountFinding struct {
	Container string
	Source    string
	Target    string
	Matched   string
	Severity  checks.Severity
}

func criticalMountSeverity(source string) (checks.Severity, string, bool) {
	source = filepath.Clean(source)
	for _, critical := range []string{"/var/run/docker.sock", "/", "/etc", "/root", "/proc", "/sys", "/var/lib/docker"} {
		if !pathMatches(source, critical) {
			continue
		}
		if critical == "/" || critical == "/var/run/docker.sock" {
			return checks.SeverityHigh, critical, true
		}
		return checks.SeverityMedium, critical, true
	}
	return "", "", false
}

func pathMatches(path, critical string) bool {
	path = filepath.Clean(path)
	critical = filepath.Clean(critical)
	if critical == "/" {
		return path == "/"
	}
	return path == critical || strings.HasPrefix(path, critical+string(filepath.Separator))
}

func highestMountSeverity(findings []mountFinding) checks.Severity {
	for _, finding := range findings {
		if finding.Severity == checks.SeverityHigh {
			return checks.SeverityHigh
		}
	}
	return checks.SeverityMedium
}

func mountEvidence(findings []mountFinding) []string {
	evidence := []string{}
	for _, finding := range findings {
		evidence = append(evidence, fmt.Sprintf("%s mount=%s:%s matched=%s", finding.Container, finding.Source, finding.Target, finding.Matched))
	}
	return evidence
}

var dangerousCaps = map[string]struct{}{
	"SYS_ADMIN":       {},
	"NET_ADMIN":       {},
	"SYS_PTRACE":      {},
	"DAC_READ_SEARCH": {},
	"SYS_MODULE":      {},
}

func dangerousCapabilities(caps []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, cap := range caps {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		cap = strings.TrimPrefix(cap, "CAP_")
		if _, dangerous := dangerousCaps[cap]; !dangerous {
			continue
		}
		if _, ok := seen[cap]; ok {
			continue
		}
		seen[cap] = struct{}{}
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}

func hasNoNewPrivileges(options []string) bool {
	for _, option := range options {
		normalized := strings.ToLower(strings.TrimSpace(option))
		if normalized == "no-new-privileges" || normalized == "no-new-privileges=true" || normalized == "no-new-privileges:true" {
			return true
		}
	}
	return false
}

func containerRunsAsRoot(user string) bool {
	user = strings.TrimSpace(strings.ToLower(user))
	if user == "" || user == "root" || user == "0" {
		return true
	}
	return strings.HasPrefix(user, "root:") || strings.HasPrefix(user, "0:")
}

func imageUsesLatest(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return false
	}
	imageWithoutDigest := image
	if before, _, ok := strings.Cut(image, "@"); ok {
		imageWithoutDigest = before
	}
	lastSlash := strings.LastIndex(imageWithoutDigest, "/")
	lastColon := strings.LastIndex(imageWithoutDigest, ":")
	if lastColon <= lastSlash {
		return false
	}
	return strings.EqualFold(imageWithoutDigest[lastColon+1:], "latest")
}

func noRestartPolicy(policy string) bool {
	policy = strings.ToLower(strings.TrimSpace(policy))
	return policy == "" || policy == "no" || policy == "none"
}

func evidenceOrNone(values []string, none string) string {
	if len(values) == 0 {
		return none
	}
	return joinEvidence(values, 10)
}

func evidenceWithCount(values []string, key string) string {
	return fmt.Sprintf("%s=%d", key, len(values))
}

func evidenceWithCountAndList(values []string, key string) string {
	if len(values) == 0 {
		return evidenceWithCount(values, key)
	}
	return evidenceWithCount(values, key) + "; " + joinEvidence(values, 10)
}

type systemDFUsage struct {
	Rows             []systemDFRow
	TotalReclaimable int64
}

type systemDFRow struct {
	Type        string
	Reclaimable string
	Bytes       int64
}

func parseSystemDF(output string) systemDFUsage {
	usage := systemDFUsage{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToUpper(line), "TYPE ") {
			continue
		}

		row, ok := parseSystemDFRow(line)
		if !ok {
			continue
		}
		usage.Rows = append(usage.Rows, row)
		usage.TotalReclaimable += row.Bytes
	}
	return usage
}

func parseSystemDFRow(line string) (systemDFRow, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return systemDFRow{}, false
	}

	sizeIndexes := []int{}
	for i, field := range fields {
		if _, ok := parseByteSize(field); ok {
			sizeIndexes = append(sizeIndexes, i)
		}
	}
	if len(sizeIndexes) < 2 {
		return systemDFRow{}, false
	}

	reclaimIndex := sizeIndexes[len(sizeIndexes)-1]
	typeFields := fields[:reclaimIndex-3]
	if len(typeFields) == 0 {
		typeFields = fields[:1]
	}
	reclaimable := fields[reclaimIndex]
	bytes, ok := parseByteSize(reclaimable)
	if !ok {
		return systemDFRow{}, false
	}

	return systemDFRow{
		Type:        strings.Join(typeFields, " "),
		Reclaimable: reclaimable,
		Bytes:       bytes,
	}, true
}

func (u systemDFUsage) evidence() string {
	parts := []string{}
	for _, row := range u.Rows {
		key := strings.ToLower(strings.ReplaceAll(row.Type, " ", "_"))
		parts = append(parts, key+"_reclaimable="+row.Reclaimable)
	}
	parts = append(parts, "total_reclaimable="+humanBytes(u.TotalReclaimable))
	return strings.Join(parts, "; ")
}

var sizeRE = regexp.MustCompile(`(?i)^([0-9]+(?:\.[0-9]+)?)(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)$`)

func parseByteSize(value string) (int64, bool) {
	value = strings.TrimSpace(strings.Trim(value, "()"))
	if value == "0" {
		return 0, true
	}
	matches := sizeRE.FindStringSubmatch(value)
	if len(matches) != 3 {
		return 0, false
	}

	number, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, false
	}

	unit := strings.ToUpper(matches[2])
	multiplier := float64(1)
	switch unit {
	case "B":
		multiplier = 1
	case "KB":
		multiplier = 1000
	case "MB":
		multiplier = 1000 * 1000
	case "GB":
		multiplier = 1000 * 1000 * 1000
	case "TB":
		multiplier = 1000 * 1000 * 1000 * 1000
	case "KIB":
		multiplier = 1024
	case "MIB":
		multiplier = 1024 * 1024
	case "GIB":
		multiplier = 1024 * 1024 * 1024
	case "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	}
	return int64(number * multiplier), true
}

type logFile struct {
	Path string
	Size int64
}

func largeJSONLogs(root string, threshold int64) ([]logFile, error) {
	logs := []logFile{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "-json.log") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > threshold {
			logs = append(logs, logFile{Path: path, Size: info.Size()})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(logs, func(i, j int) bool {
		return logs[i].Size > logs[j].Size
	})
	return logs, nil
}

func logFileEvidence(logs []logFile) []string {
	evidence := []string{}
	for _, log := range logs {
		evidence = append(evidence, fmt.Sprintf("path=%s size=%s", log.Path, humanBytes(log.Size)))
	}
	return evidence
}

func directorySize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func ensureReadablePath(result *checks.Result, path, key, missingSummary string) bool {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return true
		}
		result.Status = checks.StatusError
		result.Severity = checks.SeverityMedium
		result.Summary = key + " is not a directory."
		result.ClientSummary = "Docker storage path could not be verified."
		result.AdminDetails = "Expected directory at " + path + "."
		result.Evidence = key + "=not_directory path=" + path
		result.HiddenInClientReport = true
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		*result = notApplicable(*result, key+"=not_found path="+path, missingSummary)
		return false
	}
	result.Status = checks.StatusError
	result.Severity = checks.SeverityMedium
	result.Summary = "Docker storage path could not be read."
	result.ClientSummary = "Docker storage path could not be verified."
	result.AdminDetails = "Stat failed for " + path + "\n" + err.Error()
	result.Evidence = key + "=stat_error path=" + path
	result.Error = err.Error()
	result.HiddenInClientReport = true
	return false
}

func humanBytes(size int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(size)
	unit := units[0]
	for i := 1; i < len(units) && value >= 1024; i++ {
		value /= 1024
		unit = units[i]
	}
	if unit == "B" {
		return fmt.Sprintf("%dB", size)
	}
	return fmt.Sprintf("%.1f%s", value, unit)
}

func joinEvidence(values []string, limit int) string {
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return strings.Join(out, "; ")
}

func compactWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
