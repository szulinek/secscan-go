package varnish

import (
	"strconv"
	"strings"
)

type StatSample struct {
	Metrics map[string]float64
}

func ParseStat(output string) StatSample {
	sample := StatSample{Metrics: map[string]float64{}}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.Contains(fields[0], ".") {
			continue
		}

		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		sample.Metrics[fields[0]] = value
	}
	return sample
}

func (s StatSample) Value(names ...string) (float64, bool) {
	for _, name := range names {
		value, ok := s.Metrics[name]
		if ok {
			return value, true
		}
	}
	return 0, false
}

func (s StatSample) BackendHealth() (healthy, unhealthy int, ok bool) {
	for name, value := range s.Metrics {
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".happy") && !strings.Contains(lower, "backend_health") {
			continue
		}
		ok = true
		if value > 0 {
			healthy++
		} else {
			unhealthy++
		}
	}
	return healthy, unhealthy, ok
}
