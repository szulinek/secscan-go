package system

import (
	"net"
	"reflect"
	"testing"
)

func TestSelectHostIPsPrefersPublicAddress(t *testing.T) {
	hostIPs := selectHostIPs([]interfaceInfo{
		{
			Name:  "docker0",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "172.17.0.1/16")},
		},
		{
			Name:  "eth0",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "10.0.0.10/24")},
		},
		{
			Name:  "ens3",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "203.0.113.10/24")},
		},
	})

	if hostIPs.PrimaryIP != "203.0.113.10" {
		t.Fatalf("expected public primary IP, got %q", hostIPs.PrimaryIP)
	}
	if !reflect.DeepEqual(hostIPs.PublicIPCandidates, []string{"203.0.113.10"}) {
		t.Fatalf("unexpected public candidates: %#v", hostIPs.PublicIPCandidates)
	}
	if !reflect.DeepEqual(hostIPs.IPAddresses, []string{"203.0.113.10", "10.0.0.10"}) {
		t.Fatalf("unexpected IP list: %#v", hostIPs.IPAddresses)
	}
}

func TestSelectHostIPsIgnoresContainerBridgeInterfaces(t *testing.T) {
	hostIPs := selectHostIPs([]interfaceInfo{
		{Name: "br-abc123", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "198.51.100.10/24")}},
		{Name: "veth1234", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "198.51.100.11/24")}},
		{Name: "cni0", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "198.51.100.12/24")}},
		{Name: "flannel.1", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "198.51.100.13/24")}},
		{Name: "kube-ipvs0", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "198.51.100.14/24")}},
		{Name: "eth0", Flags: net.FlagUp, Addrs: []net.Addr{mustCIDR(t, "192.0.2.20/24")}},
	})

	if hostIPs.PrimaryIP != "192.0.2.20" {
		t.Fatalf("expected non-bridge primary IP, got %q", hostIPs.PrimaryIP)
	}
	if !reflect.DeepEqual(hostIPs.PublicIPCandidates, []string{"192.0.2.20"}) {
		t.Fatalf("unexpected public candidates: %#v", hostIPs.PublicIPCandidates)
	}
	if !reflect.DeepEqual(hostIPs.IPAddresses, []string{"192.0.2.20"}) {
		t.Fatalf("bridge interfaces should be excluded, got %#v", hostIPs.IPAddresses)
	}
}

func TestSelectHostIPsFallsBackToPrivateAddress(t *testing.T) {
	hostIPs := selectHostIPs([]interfaceInfo{
		{
			Name:  "docker0",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "172.17.0.1/16")},
		},
		{
			Name:  "eth0",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "192.168.10.25/24")},
		},
	})

	if hostIPs.PrimaryIP != "192.168.10.25" {
		t.Fatalf("expected private fallback primary IP, got %q", hostIPs.PrimaryIP)
	}
	if len(hostIPs.PublicIPCandidates) != 0 {
		t.Fatalf("expected no public candidates, got %#v", hostIPs.PublicIPCandidates)
	}
	if !reflect.DeepEqual(hostIPs.IPAddresses, []string{"192.168.10.25"}) {
		t.Fatalf("unexpected IP list: %#v", hostIPs.IPAddresses)
	}
}

func mustCIDR(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %s: %v", cidr, err)
	}
	network.IP = ip
	return network
}
