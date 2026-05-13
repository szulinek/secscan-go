package varnish

import "testing"

func TestParseStatReadsCounters(t *testing.T) {
	sample := ParseStat("MAIN.cache_hit 123\nMAIN.cache_miss 45\nMAIN.n_lru_nuked 0\n")

	if value, ok := sample.Value("MAIN.cache_hit"); !ok || value != 123 {
		t.Fatalf("unexpected cache_hit: %v %v", value, ok)
	}
	if value, ok := sample.Value("MAIN.cache_miss"); !ok || value != 45 {
		t.Fatalf("unexpected cache_miss: %v %v", value, ok)
	}
	if value, ok := sample.Value("MAIN.n_lru_nuked"); !ok || value != 0 {
		t.Fatalf("unexpected n_lru_nuked: %v %v", value, ok)
	}
}

func TestParseStatBackendHealth(t *testing.T) {
	sample := ParseStat("VBE.boot.default.happy 1\nVBE.boot.api.happy 0\n")

	healthy, unhealthy, ok := sample.BackendHealth()
	if !ok {
		t.Fatal("expected backend health metrics")
	}
	if healthy != 1 || unhealthy != 1 {
		t.Fatalf("unexpected backend health: healthy=%d unhealthy=%d", healthy, unhealthy)
	}
}
