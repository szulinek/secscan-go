package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"secscan/internal/checks"
	"secscan/internal/system"
)

func TestDetectMatchesExactSystemdUnit(t *testing.T) {
	module := New(Definition{
		ID:        "nginx",
		Name:      "Nginx",
		UnitNames: []string{"nginx.service"},
	})

	ctx := checks.Context{
		Context: context.Background(),
		Services: []system.Service{
			{Unit: "nginx.service"},
		},
	}

	if !module.Detect(ctx) {
		t.Fatal("expected nginx to be detected by exact unit")
	}
}

func TestDetectMatchesSystemdUnitGlob(t *testing.T) {
	module := New(Definition{
		ID:        "php_fpm",
		Name:      "PHP-FPM",
		UnitGlobs: []string{"php*-fpm.service"},
	})

	ctx := checks.Context{
		Context: context.Background(),
		Services: []system.Service{
			{Unit: "php8.2-fpm.service"},
		},
	}

	if !module.Detect(ctx) {
		t.Fatal("expected php-fpm to be detected by unit glob")
	}
}

func TestDetectMatchesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directadmin.conf")
	if err := os.WriteFile(path, []byte("ok\n"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	module := New(Definition{
		ID:          "directadmin",
		Name:        "DirectAdmin",
		DetectPaths: []string{path},
	})

	ctx := checks.Context{Context: context.Background()}
	if !module.Detect(ctx) {
		t.Fatal("expected module to be detected by existing path")
	}
}

func TestDetectMatchesExistingPathGlob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php-fpm.conf")
	if err := os.WriteFile(path, []byte("ok\n"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	module := New(Definition{
		ID:              "php_fpm",
		Name:            "PHP-FPM",
		DetectPathGlobs: []string{filepath.Join(dir, "php-*.conf")},
	})

	ctx := checks.Context{Context: context.Background()}
	if !module.Detect(ctx) {
		t.Fatal("expected module to be detected by existing path glob")
	}
}

func TestServiceDetectedCheckReturnsInfo(t *testing.T) {
	module := New(Definition{
		ID:        "redis",
		Name:      "Redis",
		Service:   "redis",
		UnitNames: []string{"redis-server.service"},
	})

	ctx := checks.Context{
		Context: context.Background(),
		Services: []system.Service{
			{Unit: "redis-server.service"},
		},
	}

	result := module.Checks()[0].Run(ctx)
	if result.Status != checks.StatusInfo {
		t.Fatalf("expected info status, got %s", result.Status)
	}

	if result.ID != "redis.service_detected" {
		t.Fatalf("unexpected check id: %s", result.ID)
	}

	if result.Evidence != "running_service=redis-server.service" {
		t.Fatalf("unexpected evidence: %s", result.Evidence)
	}
}
