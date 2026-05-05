package linux

import "testing"

func TestIPTablesLooksConfigured(t *testing.T) {
	if iptablesLooksConfigured("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n") {
		t.Fatal("default ACCEPT policies should not be treated as configured firewall rules")
	}

	if !iptablesLooksConfigured("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n") {
		t.Fatal("DROP policy and explicit rules should be treated as configured firewall rules")
	}
}
