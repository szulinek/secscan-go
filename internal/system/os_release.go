package system

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

const OSReleasePath = "/etc/os-release"

type Info struct {
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
	}

	values, err := ReadOSRelease(OSReleasePath)
	if err != nil {
		info.OSReleaseError = err.Error()
		return info
	}

	info.OSRelease = values
	return info
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
