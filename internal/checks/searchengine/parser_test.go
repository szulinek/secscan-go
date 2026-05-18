package searchengine

import (
	"strings"
	"testing"
)

func TestParseConfigSimpleYAML(t *testing.T) {
	config := ParseConfig(strings.Join([]string{
		"# comment",
		`network.host: "127.0.0.1" # trailing`,
		`path.repo: ["/backup/es", "/backup/os"]`,
		`xpack.security.enabled: true`,
		`cluster.name: "prod # one"`,
	}, "\n"), "/etc/elasticsearch/elasticsearch.yml")

	if got := config.StringValue("network.host"); got != "127.0.0.1" {
		t.Fatalf("unexpected network.host: %q", got)
	}
	repos := config.ListValue("path.repo")
	if len(repos) != 2 || repos[0] != "/backup/es" || repos[1] != "/backup/os" {
		t.Fatalf("unexpected path.repo values: %#v", repos)
	}
	value, ok := config.BoolValue("xpack.security.enabled")
	if !ok || !value {
		t.Fatalf("expected xpack.security.enabled=true, got %v/%v", value, ok)
	}
	if got := config.StringValue("cluster.name"); got != "prod # one" {
		t.Fatalf("quoted comment content was not preserved: %q", got)
	}
}

func TestParseJVMOptions(t *testing.T) {
	options := ParseJVMOptions(strings.Join([]string{
		"# -Xmx4g",
		"17:-Xms2g",
		"-Xmx2g",
	}, "\n"), "/etc/elasticsearch/jvm.options")

	if options.Xms != "2g" || options.Xmx != "2g" {
		t.Fatalf("unexpected JVM options: %#v", options)
	}
	if len(options.Files) != 1 {
		t.Fatalf("expected source file to be recorded")
	}
}
