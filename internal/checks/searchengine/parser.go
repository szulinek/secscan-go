package searchengine

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
	Key   string
	Value string
	Path  string
	Line  int
}

func ParseConfig(content, path string) Config {
	config := Config{Values: map[string][]ConfigValue{}}
	for index, raw := range strings.Split(content, "\n") {
		line := stripComment(raw)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		item := ConfigValue{
			Key:   key,
			Value: normalizeValue(value),
			Path:  path,
			Line:  index + 1,
		}
		config.Values[key] = append(config.Values[key], item)
	}
	return config
}

func loadConfigFromPaths(paths []string) (Config, error) {
	config := Config{Values: map[string][]ConfigValue{}}
	found := false
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		found = true
		data, err := os.ReadFile(path)
		if err != nil {
			return config, err
		}
		parsed := ParseConfig(string(data), path)
		config.Files = append(config.Files, path)
		for key, values := range parsed.Values {
			config.Values[key] = append(config.Values[key], values...)
		}
	}
	if !found {
		return config, os.ErrNotExist
	}
	return config, nil
}

func (c Config) ValuesFor(key string) []ConfigValue {
	return c.Values[strings.ToLower(strings.TrimSpace(key))]
}

func (c Config) LastValue(key string) (ConfigValue, bool) {
	values := c.ValuesFor(key)
	if len(values) == 0 {
		return ConfigValue{}, false
	}
	return values[len(values)-1], true
}

func (c Config) StringValue(key string) string {
	value, ok := c.LastValue(key)
	if !ok {
		return ""
	}
	return value.Value
}

func (c Config) BoolValue(key string) (bool, bool) {
	value := c.StringValue(key)
	if value == "" {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1", "enabled":
		return true, true
	case "false", "no", "off", "0", "disabled":
		return false, true
	default:
		return false, false
	}
}

func (c Config) ListValue(key string) []string {
	value := c.StringValue(key)
	if value == "" {
		return nil
	}
	return parseListValue(value)
}

type JVMOptions struct {
	Xms   string
	Xmx   string
	Files []string
}

func ParseJVMOptions(content, path string) JVMOptions {
	options := JVMOptions{}
	for _, raw := range strings.Split(content, "\n") {
		line := stripComment(raw)
		if line == "" {
			continue
		}
		if idx := strings.LastIndex(line, "-Xms"); idx >= 0 {
			options.Xms = strings.TrimSpace(line[idx+4:])
			continue
		}
		if idx := strings.LastIndex(line, "-Xmx"); idx >= 0 {
			options.Xmx = strings.TrimSpace(line[idx+4:])
		}
	}
	if options.Xms != "" || options.Xmx != "" {
		options.Files = append(options.Files, path)
	}
	return options
}

func loadJVMOptionsFromPatterns(patterns []string) (JVMOptions, error) {
	options := JVMOptions{}
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
			data, err := os.ReadFile(path)
			if err != nil {
				return options, err
			}
			parsed := ParseJVMOptions(string(data), path)
			if parsed.Xms != "" {
				options.Xms = parsed.Xms
			}
			if parsed.Xmx != "" {
				options.Xmx = parsed.Xmx
			}
			options.Files = append(options.Files, path)
		}
	}
	if !found {
		return options, os.ErrNotExist
	}
	return options, nil
}

func stripComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
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
		if r == '#' {
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

func parseListValue(value string) []string {
	value = normalizeValue(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	parts := splitCommaAware(value)
	out := []string{}
	for _, part := range parts {
		part = normalizeValue(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitCommaAware(value string) []string {
	parts := []string{}
	var current strings.Builder
	inQuote := false
	quote := rune(0)
	for _, r := range value {
		if inQuote {
			if r == quote {
				inQuote = false
			}
			current.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = true
			quote = r
			current.WriteRune(r)
			continue
		}
		if r == ',' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	parts = append(parts, current.String())
	return parts
}
