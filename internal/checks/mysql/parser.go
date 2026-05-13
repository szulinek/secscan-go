package mysql

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	Values map[string][]ConfigValue
	Files  []string
}

type ConfigValue struct {
	Section string
	Key     string
	Value   string
	Path    string
	Line    int
	Flag    bool
}

func ParseConfig(content, path string) Config {
	config := Config{Values: map[string][]ConfigValue{}}
	parseConfigContent(content, path, &config, nil)
	return config
}

func loadConfigFromPatterns(patterns []string) (Config, error) {
	config := Config{Values: map[string][]ConfigValue{}}
	seen := map[string]bool{}
	found := false

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			if _, statErr := os.Stat(pattern); statErr == nil {
				matches = []string{pattern}
			}
		}
		sort.Strings(matches)
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			found = true
			if err := loadConfigFile(path, &config, seen); err != nil {
				return config, err
			}
		}
	}

	if !found {
		return config, os.ErrNotExist
	}
	return config, nil
}

func loadConfigFile(path string, config *Config, seen map[string]bool) error {
	clean := filepath.Clean(path)
	if seen[clean] {
		return nil
	}
	seen[clean] = true

	data, err := os.ReadFile(clean)
	if err != nil {
		return err
	}
	config.Files = append(config.Files, clean)
	parseConfigContent(string(data), clean, config, func(include includeDirective) {
		if !safeIncludePath(include.Path) {
			return
		}
		if include.Dir {
			matches, err := filepath.Glob(filepath.Join(include.Path, "*.cnf"))
			if err != nil {
				return
			}
			sort.Strings(matches)
			for _, match := range matches {
				if info, err := os.Stat(match); err == nil && !info.IsDir() {
					_ = loadConfigFile(match, config, seen)
				}
			}
			return
		}
		if info, err := os.Stat(include.Path); err == nil && !info.IsDir() {
			_ = loadConfigFile(include.Path, config, seen)
		}
	})
	return nil
}

type includeDirective struct {
	Path string
	Dir  bool
}

func parseConfigContent(content, path string, config *Config, include func(includeDirective)) {
	section := ""
	for index, raw := range strings.Split(content, "\n") {
		line := stripConfigComment(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "!includedir") || strings.HasPrefix(lower, "!include") {
			if include != nil {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					include(includeDirective{
						Path: normalizeValue(strings.Join(parts[1:], " ")),
						Dir:  strings.HasPrefix(lower, "!includedir"),
					})
				}
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1:strings.Index(line, "]")]))
			continue
		}

		key, value, hasValue := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		item := ConfigValue{
			Section: section,
			Key:     key,
			Value:   "true",
			Path:    path,
			Line:    index + 1,
			Flag:    !hasValue,
		}
		if hasValue {
			item.Value = normalizeValue(value)
		}
		config.Values[section+"."+key] = append(config.Values[section+"."+key], item)
	}
}

func (c Config) ValuesFor(key string, sections ...string) []ConfigValue {
	key = strings.ToLower(strings.TrimSpace(key))
	values := []ConfigValue{}
	for _, section := range sections {
		values = append(values, c.Values[strings.ToLower(section)+"."+key]...)
	}
	return values
}

func (c Config) LastValue(key string, sections ...string) (ConfigValue, bool) {
	values := c.ValuesFor(key, sections...)
	if len(values) == 0 {
		return ConfigValue{}, false
	}
	return values[len(values)-1], true
}

func stripConfigComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return ""
	}

	inQuote := false
	quote := rune(0)
	escaped := false
	for index, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			escaped = true
			continue
		}
		if inQuote {
			if r == quote {
				inQuote = false
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = true
			quote = r
			continue
		}
		if r == '#' || r == ';' {
			return strings.TrimSpace(line[:index])
		}
	}
	return strings.TrimSpace(line)
}

func normalizeValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return strings.TrimSpace(value)
}

func safeIncludePath(path string) bool {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return false
		}
	}
	return true
}
