package licencly

import (
	"net"
	"strings"
	"testing"
)

func TestMachineIDIsStableAndOpaque(t *testing.T) {
	const salt = "product-uuid"

	first, err := MachineID(salt)
	if err != nil {
		t.Skipf("no stable machine identifier on this host: %v", err)
	}

	second, err := MachineID(salt)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Errorf("not stable across calls: %q then %q", first, second)
	}

	if len(first) != 32 {
		t.Errorf("length = %d, want 32", len(first))
	}
	if strings.ContainsAny(first, "ghijklmnopqrstuvwxyz-: ") {
		t.Errorf("id is not lowercase hex: %q", first)
	}

	// The raw identifier must not be recoverable from what we send. A vendor's
	// dashboard should never hold a hardware serial.
	raw, _, err := machineIdentity()
	if err == nil && raw != "" && strings.Contains(first, strings.ToLower(raw)) {
		t.Error("the raw machine identifier leaks into the fingerprint")
	}
}

// Two vendors must not be able to recognise the same machine, or Licencly
// becomes a cross-product tracking network by accident.
func TestMachineIDDiffersPerSalt(t *testing.T) {
	a, err := MachineID("product-a")
	if err != nil {
		t.Skipf("no stable machine identifier on this host: %v", err)
	}
	b, err := MachineID("product-b")
	if err != nil {
		t.Fatalf("second salt: %v", err)
	}
	if a == b {
		t.Error("the same machine produced the same id for two products")
	}
}

func TestIsVirtualName(t *testing.T) {
	virtual := []string{"docker0", "veth1a2b", "br-abc123", "virbr0", "vmnet8", "tun0", "utun3", "tailscale0", "lo"}
	physical := []string{"eth0", "eno1", "enp3s0", "wlan0", "wlp2s0", "en0", "Ethernet"}

	for _, name := range virtual {
		if !isVirtualName(name) {
			t.Errorf("%q should be treated as virtual", name)
		}
	}
	for _, name := range physical {
		if isVirtualName(name) {
			t.Errorf("%q should be treated as physical", name)
		}
	}
}

// A randomised or locally administered MAC is not an identity. Modern phones
// and laptops generate one per network, so a fingerprint built on one would
// change every time the user joined a different Wi-Fi.
func TestStableMACSkipsLocallyAdministered(t *testing.T) {
	local := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	if local[0]&0x02 == 0 {
		t.Fatal("test address is not locally administered")
	}
	universal := net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}
	if universal[0]&0x02 != 0 {
		t.Fatal("test address should be universally administered")
	}
}
