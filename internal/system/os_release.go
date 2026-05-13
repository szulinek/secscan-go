package system

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

const OSReleasePath = "/etc/os-release"

type Info struct {
	Hostname           string            `json:"hostname,omitempty"`
	PrimaryIP          string            `json:"primary_ip,omitempty"`
	PublicIPCandidates []string          `json:"public_ip_candidates,omitempty"`
	IPAddresses        []string          `json:"ip_addresses,omitempty"`
	GOOS               string            `json:"goos"`
	GOARCH             string            `json:"goarch"`
	OSReleasePath      string            `json:"os_release_path"`
	OSRelease          map[string]string `json:"os_release"`
	OSReleaseError     string            `json:"os_release_error,omitempty"`
}

func DetectInfo() Info {
	hostIPs := DetectHostIPs()
	info := Info{
		GOOS:               runtime.GOOS,
		GOARCH:             runtime.GOARCH,
		OSReleasePath:      OSReleasePath,
		OSRelease:          map[string]string{},
		PrimaryIP:          hostIPs.PrimaryIP,
		PublicIPCandidates: hostIPs.PublicIPCandidates,
		IPAddresses:        hostIPs.IPAddresses,
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	values, err := ReadOSRelease(OSReleasePath)
	if err != nil {
		info.OSReleaseError = err.Error()
		return info
	}

	info.OSRelease = values
	return info
}

type HostIPs struct {
	PrimaryIP          string
	PublicIPCandidates []string
	IPAddresses        []string
}

func DetectIPAddresses() []string {
	return DetectHostIPs().IPAddresses
}

func DetectHostIPs() HostIPs {
	interfaces, err := systemInterfaces()
	if err != nil {
		return HostIPs{}
	}
	return selectHostIPs(interfaces)
}

type interfaceInfo struct {
	Name  string
	Flags net.Flags
	Addrs []net.Addr
}

type ipCandidate struct {
	IP             net.IP
	Value          string
	InterfaceIndex int
	AddressIndex   int
	Public         bool
	Private        bool
}

func systemInterfaces() ([]interfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	out := make([]interfaceInfo, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		out = append(out, interfaceInfo{
			Name:  iface.Name,
			Flags: iface.Flags,
			Addrs: addrs,
		})
	}
	return out, nil
}

func selectHostIPs(interfaces []interfaceInfo) HostIPs {
	seen := map[string]struct{}{}
	candidates := []ipCandidate{}
	for ifaceIndex, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ignoredInterfaceName(iface.Name) {
			continue
		}

		for addrIndex, addr := range iface.Addrs {
			ip := addressIP(addr)
			if ip == nil || !isReportableIP(ip) {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}

			value := ip.String()
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			candidates = append(candidates, ipCandidate{
				IP:             ip,
				Value:          value,
				InterfaceIndex: ifaceIndex,
				AddressIndex:   addrIndex,
				Public:         isPublicIP(ip),
				Private:        ip.IsPrivate(),
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidatePriority(candidates[i])
		right := candidatePriority(candidates[j])
		if left != right {
			return left > right
		}
		if candidates[i].InterfaceIndex != candidates[j].InterfaceIndex {
			return candidates[i].InterfaceIndex < candidates[j].InterfaceIndex
		}
		return candidates[i].AddressIndex < candidates[j].AddressIndex
	})

	result := HostIPs{}
	for _, candidate := range candidates {
		result.IPAddresses = append(result.IPAddresses, candidate.Value)
		if candidate.Public {
			result.PublicIPCandidates = append(result.PublicIPCandidates, candidate.Value)
		}
	}
	if len(candidates) > 0 {
		result.PrimaryIP = candidates[0].Value
	}
	return result
}

func ignoredInterfaceName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "docker0" {
		return true
	}
	for _, prefix := range []string{"br-", "veth", "cni", "flannel", "kube"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func candidatePriority(candidate ipCandidate) int {
	switch {
	case candidate.Public && candidate.IP.To4() != nil:
		return 400
	case candidate.Public:
		return 300
	case candidate.Private && candidate.IP.To4() != nil:
		return 200
	case candidate.Private:
		return 100
	default:
		return 10
	}
}

func addressIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func isReportableIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast()
}

func isPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func ReadOSRelease(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key != "" {
			values[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return values, nil
}
