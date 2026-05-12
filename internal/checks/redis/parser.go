package redis

import "strings"

type Config struct {
	Directives map[string][]Directive
}

type Directive struct {
	Key    string
	Values []string
	Raw    string
}

func ParseConfig(content string) Config {
	config := Config{Directives: map[string][]Directive{}}
	for _, line := range strings.Split(content, "\n") {
		clean := strings.TrimSpace(stripComment(line))
		if clean == "" {
			continue
		}

		tokens := splitRedisFields(clean)
		if len(tokens) == 0 {
			continue
		}

		key := strings.ToLower(tokens[0])
		directive := Directive{
			Key:    key,
			Values: tokens[1:],
			Raw:    clean,
		}
		config.Directives[key] = append(config.Directives[key], directive)
	}
	return config
}

func (c Config) Values(key string) []Directive {
	return c.Directives[strings.ToLower(key)]
}

func (c Config) LastValue(key string) (Directive, bool) {
	values := c.Values(key)
	if len(values) == 0 {
		return Directive{}, false
	}
	return values[len(values)-1], true
}

func stripComment(line string) string {
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
			return line[:index]
		}
	}
	return line
}

func splitRedisFields(line string) []string {
	fields := []string{}
	var current strings.Builder
	inQuote := false
	quote := rune(0)
	escaped := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		fields = append(fields, current.String())
		current.Reset()
	}

	for _, r := range line {
		if escaped {
			current.WriteRune(r)
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
				continue
			}
			current.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = true
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	flush()
	return fields
}
