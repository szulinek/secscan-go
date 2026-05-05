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
	Hostname       string            `json:"hostname,omitempty"`
	IPAddresses    []string          `json:"ip_addresses,omitempty"`
	GOOS           string            `json:"goos"`
	GOARCH         string            `json:"goarch"`
	OSReleasePath  string            `json:"os_release_path"`
	OSRelease      map[string]string `json:"os_release"`
	OSReleaseError string            `json:"os_release_error,omitempty"`
}

func DetectInfo() Info {
	info := Info{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		OSReleasePath: OSReleasePath,
		OSRelease:     map[string]string{},
		IPAddresses:   DetectIPAddresses(),
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

func DetectIPAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}

	seen := map[string]struct{}{}
	var ips []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
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
			ips = append(ips, value)
		}
	}

	sort.Strings(ips)
	return ips
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
		!ip.IsLinkLocalMulticast()
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
