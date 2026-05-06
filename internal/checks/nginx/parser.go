package nginx

import (
	"regexp"
	"sort"
	"strings"
)

type Config struct {
	Raw   string
	Clean string
}

type LocationBlock struct {
	Header string
	Body   string
}

func ParseConfig(raw string) Config {
	lines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(stripComment(line))
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}

	return Config{
		Raw:   raw,
		Clean: strings.Join(lines, "\n"),
	}
}

func (c Config) DirectiveMatches(re *regexp.Regexp) []string {
	matches := re.FindAllStringSubmatch(c.Clean, -1)
	values := []string{}
	for _, match := range matches {
		if len(match) == 0 {
			continue
		}
		values = append(values, compactWhitespace(match[0]))
	}
	return values
}

func (c Config) LocationBlocks() []LocationBlock {
	return c.Blocks("location")
}

func (c Config) Blocks(name string) []LocationBlock {
	clean := c.Clean
	lower := strings.ToLower(clean)
	blocks := []LocationBlock{}
	needle := strings.ToLower(name)
	offset := 0
	for {
		index := strings.Index(lower[offset:], needle)
		if index < 0 {
			break
		}
		start := offset + index
		if !isBlockKeyword(clean, start, len(needle)) {
			offset = start + len(needle)
			continue
		}
		open := strings.Index(clean[start:], "{")
		if open < 0 {
			break
		}
		open += start
		close := matchingBrace(clean, open)
		if close < 0 {
			offset = open + 1
			continue
		}

		blocks = append(blocks, LocationBlock{
			Header: compactWhitespace(clean[start:open]),
			Body:   clean[open+1 : close],
		})
		offset = close + 1
	}
	return blocks
}

func isBlockKeyword(value string, start, length int) bool {
	if start > 0 {
		before := value[start-1]
		if before == '_' || before == '-' || (before >= 'A' && before <= 'Z') || (before >= 'a' && before <= 'z') {
			return false
		}
	}
	after := start + length
	if after >= len(value) {
		return false
	}
	next := value[after]
	return next == ' ' || next == '\t' || next == '\n' || next == '{'
}

func matchingBrace(value string, open int) int {
	depth := 0
	for i := open; i < len(value); i++ {
		switch value[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (c Config) AddHeaders() []string {
	matches := addHeaderRE.FindAllStringSubmatch(c.Clean, -1)
	headers := []string{}
	seen := map[string]struct{}{}
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		header := canonicalHeader(match[1])
		if _, ok := seen[header]; ok {
			continue
		}
		seen[header] = struct{}{}
		headers = append(headers, header)
	}
	sort.Strings(headers)
	return headers
}

func canonicalHeader(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x-frame-options":
		return "X-Frame-Options"
	case "x-content-type-options":
		return "X-Content-Type-Options"
	case "referrer-policy":
		return "Referrer-Policy"
	case "content-security-policy":
		return "Content-Security-Policy"
	default:
		return strings.TrimSpace(value)
	}
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if char == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if char == '#' && !inSingle && !inDouble {
			return line[:i]
		}
	}
	return line
}

func compactWhitespace(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}
