package smtpreport

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseRecipients(t *testing.T) {
	got := ParseRecipients("client@example.com, admin@example.com;ops@example.com\nteam@example.com")
	want := []string{"client@example.com", "admin@example.com", "ops@example.com", "team@example.com"}
	if len(got) != len(want) {
		t.Fatalf("expected %d recipients, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recipient %d: expected %s, got %s", i, want[i], got[i])
		}
	}
}

func TestBuildMessageIncludesPDFAttachment(t *testing.T) {
	config := Config{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "audit@example.com",
		FromName: "Audit",
	}
	message := Message{
		To:             []string{"client@example.com"},
		Subject:        "Security Audit Report",
		Body:           "Raport w załączniku.",
		AttachmentName: "report.pdf",
		Attachment:     []byte("%PDF-test"),
	}

	payload, err := buildMessage(config, message)
	if err != nil {
		t.Fatalf("build message: %v", err)
	}

	value := string(payload)
	for _, needle := range []string{
		"Content-Type: multipart/mixed;",
		"Content-Type: application/pdf; name=\"report.pdf\"",
		"Content-Disposition: attachment; filename=\"report.pdf\"",
		base64.StdEncoding.EncodeToString(message.Attachment),
	} {
		if !strings.Contains(value, needle) {
			t.Fatalf("expected message to contain %q", needle)
		}
	}
}

func TestValidateRequiresRecipient(t *testing.T) {
	err := validate(Config{Host: "smtp.example.com", Port: 587, From: "audit@example.com"}, Message{
		AttachmentName: "report.pdf",
		Attachment:     []byte("%PDF"),
	})
	if err == nil || !strings.Contains(err.Error(), "recipient is required") {
		t.Fatalf("expected recipient validation error, got %v", err)
	}
}
