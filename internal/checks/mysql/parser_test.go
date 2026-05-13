package mysql

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigSectionsFlagsAndComments(t *testing.T) {
	config := ParseConfig(`
# top comment
[client]
user = backup

[mysqld]
bind-address = "127.0.0.1" # inline
skip-networking
max_connections=250
ssl-ca = '/etc/mysql/ca.pem'
; ignored
`, "/etc/mysql/my.cnf")

	if got := serverSetting(config, "bind-address").Value; got != "127.0.0.1" {
		t.Fatalf("bind-address: expected 127.0.0.1, got %q", got)
	}
	if !serverFlag(config, "skip-networking") {
		t.Fatal("expected skip-networking flag")
	}
	if got := serverSetting(config, "max_connections").Value; got != "250" {
		t.Fatalf("max_connections: expected 250, got %q", got)
	}
	if got := serverSetting(config, "ssl-ca").Value; got != "/etc/mysql/ca.pem" {
		t.Fatalf("ssl-ca: expected normalized value, got %q", got)
	}
	if client := config.ValuesFor("user", "client"); len(client) != 1 || client[0].Value != "backup" {
		t.Fatalf("expected client user value, got %#v", client)
	}
}

func TestLoadConfigIncludesFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "my.cnf")
	includeDir := filepath.Join(root, "conf.d")
	includeFile := filepath.Join(root, "extra.cnf")
	writeParserFile(t, filepath.Join(includeDir, "server.cnf"), "[mysqld]\nmax_connections=320\n")
	writeParserFile(t, includeFile, "[server]\nskip-name-resolve\n")
	writeParserFile(t, main, "[mysqld]\nbind-address=127.0.0.1\n!includedir "+includeDir+"\n!include "+includeFile+"\n")

	config, err := loadConfigFromPatterns([]string{main})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := serverSetting(config, "max_connections").Value; got != "320" {
		t.Fatalf("expected included max_connections, got %q", got)
	}
	if !serverFlag(config, "skip-name-resolve") {
		t.Fatal("expected included skip-name-resolve")
	}
	if len(config.Files) != 3 {
		t.Fatalf("expected 3 loaded files, got %d: %#v", len(config.Files), config.Files)
	}
}

func writeParserFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
