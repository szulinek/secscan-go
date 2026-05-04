package system

import "testing"

func TestParseSystemctlListUnits(t *testing.T) {
	output := `
ssh.service loaded active running OpenBSD Secure Shell server
nginx.service loaded active running A high performance web server
`

	services := ParseSystemctlListUnits(output)
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	if services[0].Unit != "ssh.service" {
		t.Fatalf("unexpected first unit: %s", services[0].Unit)
	}

	if services[1].Description != "A high performance web server" {
		t.Fatalf("unexpected description: %s", services[1].Description)
	}

	if !HasRunningService(services, "ssh.service", "sshd.service") {
		t.Fatal("expected ssh service to be detected")
	}
}
