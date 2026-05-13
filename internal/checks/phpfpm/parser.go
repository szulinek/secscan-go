package phpfpm

import "strings"

type INIConfig struct {
	Values map[string]string
}

type PoolFile struct {
	Version   string
	Source    string
	Path      string
	Pools     []PoolConfig
	ReadError error
}

type PoolConfig struct {
	Version        string
	Source         string
	Path           string
	Pool           string
	Values         map[string]string
	PHPAdminValues map[string]string
	PHPValues      map[string]string
}

func ParseINI(content string) INIConfig {
	config := INIConfig{Values: map[string]string{}}
	for _, line := range strings.Split(content, "\n") {
		line = stripConfigComment(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		config.Values[key] = normalizeValue(value)
	}
	return config
}

func ParsePoolConfig(version, source, path, content string) []PoolConfig {
	current := newPool(version, source, path, poolName(path))
	pools := []PoolConfig{}
	hasSection := false
	hasData := false

	flush := func() {
		if hasSection || hasData {
			pools = append(pools, current)
		}
	}

	for _, line := range strings.Split(content, "\n") {
		line = stripConfigComment(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			flush()
			name := strings.TrimSpace(line[1:strings.Index(line, "]")])
			current = newPool(version, source, path, name)
			hasSection = true
			hasData = false
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		assignPoolValue(&current, key, value)
		hasData = true
	}
	flush()
	return pools
}

func newPool(version, source, path, name string) PoolConfig {
	if strings.TrimSpace(name) == "" {
		name = "default"
	}
	return PoolConfig{
		Version:        version,
		Source:         source,
		Path:           path,
		Pool:           name,
		Values:         map[string]string{},
		PHPAdminValues: map[string]string{},
		PHPValues:      map[string]string{},
	}
}

func assignPoolValue(pool *PoolConfig, key, value string) {
	key = strings.TrimSpace(key)
	value = normalizeValue(value)
	lower := strings.ToLower(key)

	if name, ok := bracketName(lower, "php_admin_value"); ok {
		pool.PHPAdminValues[name] = value
		return
	}
	if name, ok := bracketName(lower, "php_value"); ok {
		pool.PHPValues[name] = value
		return
	}
	if lower == "" {
		return
	}
	pool.Values[lower] = value
}

func bracketName(key, prefix string) (string, bool) {
	expected := prefix + "["
	if !strings.HasPrefix(key, expected) || !strings.HasSuffix(key, "]") {
		return "", false
	}
	name := strings.TrimSpace(key[len(expected) : len(key)-1])
	return name, name != ""
}

func stripConfigComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
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
		if r == ';' || r == '#' {
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
