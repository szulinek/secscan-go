package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeRemediationMetadata(t *testing.T) {
	result := Result{
		ID:          "x",
		Summary:     "summary",
		Remediation: "Fix it.",
		RemediationSteps: []string{
			" first ",
			"",
			"second",
			"third",
			"fourth",
			"fifth",
			"sixth",
		},
		References: []string{" https://example.com ", ""},
	}

	result.Normalize()
	if result.Recommendation != "Fix it." {
		t.Fatalf("expected recommendation copied from remediation, got %q", result.Recommendation)
	}
	if len(result.RemediationSteps) != 5 {
		t.Fatalf("expected remediation steps capped at 5, got %#v", result.RemediationSteps)
	}
	if result.RemediationSteps[0] != "first" {
		t.Fatalf("expected trimmed remediation step, got %#v", result.RemediationSteps)
	}
	if len(result.References) != 1 || result.References[0] != "https://example.com" {
		t.Fatalf("unexpected references: %#v", result.References)
	}
}

func TestResultJSONSerializesRemediationMetadata(t *testing.T) {
	result := Result{
		ID:               "x",
		RemediationSteps: []string{"Edit config", "Reload service"},
		References:       []string{"https://example.com"},
		Automation: Automation{
			Shell:   "echo ok",
			Ansible: "- debug: msg=ok",
			Chef:    "log 'ok'",
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	value := string(payload)
	for _, needle := range []string{
		`"remediation_steps":["Edit config","Reload service"]`,
		`"references":["https://example.com"]`,
		`"automation":{"shell":"echo ok","ansible":"- debug: msg=ok","chef":"log 'ok'"}`,
	} {
		if !strings.Contains(value, needle) {
			t.Fatalf("expected JSON to contain %s, got %s", needle, value)
		}
	}
}
