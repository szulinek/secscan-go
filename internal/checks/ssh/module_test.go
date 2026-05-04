package ssh

import "testing"

func TestParseSSHDConfig(t *testing.T) {
	values := parseSSHDConfig(`
permitrootlogin no
passwordauthentication yes
permitemptypasswords no
`)

	if values["permitrootlogin"] != "no" {
		t.Fatalf("unexpected permitrootlogin: %s", values["permitrootlogin"])
	}

	if values["passwordauthentication"] != "yes" {
		t.Fatalf("unexpected passwordauthentication: %s", values["passwordauthentication"])
	}

	if values["permitemptypasswords"] != "no" {
		t.Fatalf("unexpected permitemptypasswords: %s", values["permitemptypasswords"])
	}
}
