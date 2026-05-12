package redis

import (
	"strings"
	"testing"
)

func TestParseConfigIgnoresCommentsAndHandlesQuotes(t *testing.T) {
	config := ParseConfig(strings.Join([]string{
		"# bind 0.0.0.0",
		`bind 127.0.0.1 "localhost" # trailing comment`,
		`requirepass "secret # not comment"`,
		`maxmemory 512mb`,
	}, "\n"))

	bind, ok := config.LastValue("bind")
	if !ok {
		t.Fatal("expected bind directive")
	}
	if got := strings.Join(bind.Values, ","); got != "127.0.0.1,localhost" {
		t.Fatalf("unexpected bind values: %s", got)
	}

	requirePass, ok := config.LastValue("requirepass")
	if !ok || len(requirePass.Values) != 1 || requirePass.Values[0] != "secret # not comment" {
		t.Fatalf("quoted requirepass was not parsed correctly: %#v", requirePass)
	}

	if _, ok := config.LastValue("#"); ok {
		t.Fatal("comment should not become a directive")
	}
}

func TestParseConfigKeepsMultipleSaveDirectives(t *testing.T) {
	config := ParseConfig(strings.Join([]string{
		"save 900 1",
		"save 300 10",
		`save ""`,
	}, "\n"))

	save := config.Values("save")
	if len(save) != 3 {
		t.Fatalf("expected 3 save directives, got %d", len(save))
	}
	if got := strings.Join(save[0].Values, " "); got != "900 1" {
		t.Fatalf("unexpected first save directive: %s", got)
	}
	if len(save[2].Values) != 0 {
		t.Fatalf("disabled save directive should have no values, got %#v", save[2].Values)
	}
}
