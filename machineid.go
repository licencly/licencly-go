package licencly

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ErrNoMachineID is returned when no stable identifier could be read. It is
// rare, and it means machine binding is not available on that host rather than
// that anything is wrong: handle it by validating without a fingerprint.
var ErrNoMachineID = errors.New("licencly: no stable machine identifier found")

// MachineID returns a stable, hashed identifier for the machine it runs on,
// suitable for Config.Fingerprint. It reads, in order:
//
//   - Linux: /etc/machine-id, then /var/lib/dbus/machine-id
//   - macOS: IOPlatformUUID
//   - Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
//   - anywhere: the MAC address of the first physical network interface
//
// The operating system's identifier is preferred over a MAC deliberately. A MAC
// changes with a dock or a USB adapter, Wi-Fi MACs are randomised per network,
// and a machine running Docker or a VPN has several. The OS identifier survives
// all of that and a hardware upgrade, and does not survive being copied to
// another machine, which is the line a seat limit wants.
//
// The result is hashed with salt, so no hardware identifier leaves the machine
// and the same computer looks different to every vendor. Pass your product
// UUID: it is stable and already public.
//
//	fp, err := licencly.MachineID(productUUID)
//	if err != nil {
//	    fp = "" // no machine binding on this host
//	}
func MachineID(salt string) (string, error) {
	raw, source, err := machineIdentity()
	if err != nil {
		return "", err
	}

	// The source is mixed in so a MAC address and an OS identifier that happen
	// to be the same string could never collide.
	sum := sha256.Sum256([]byte(salt + "\x00" + source + "\x00" + raw))
	return hex.EncodeToString(sum[:])[:32], nil
}

// machineIdentity returns the rawest identifier available and where it came
// from. Kept separate from the hashing so it can be tested directly.
func machineIdentity() (raw, source string, err error) {
	switch runtime.GOOS {
	case "linux":
		// systemd writes the first; the second is the older D-Bus location and
		// is still the only one present on some minimal images.
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if id := readTrimmed(path); id != "" {
				return id, "machine-id", nil
			}
		}
	case "darwin":
		if id := darwinPlatformUUID(); id != "" {
			return id, "ioplatformuuid", nil
		}
	case "windows":
		if id := windowsMachineGUID(); id != "" {
			return id, "machineguid", nil
		}
	}

	if mac := stableMAC(); mac != "" {
		return mac, "mac", nil
	}
	return "", "", ErrNoMachineID
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// darwinPlatformUUID reads the hardware UUID macOS assigns to the logic board.
func darwinPlatformUUID() string {
	out, err := runCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		// The line looks like:  "IOPlatformUUID" = "0A1B2C3D-..."
		if i := strings.Index(line, "= \""); i >= 0 {
			if id := strings.Trim(line[i+2:], " \""); id != "" {
				return id
			}
		}
	}
	return ""
}

// windowsMachineGUID reads the value Windows generates at install time.
//
// Shelling out to reg.exe rather than reading the registry directly keeps this
// SDK free of dependencies, which matters more than the cost of one process at
// startup.
func windowsMachineGUID() string {
	out, err := runCommand("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "MachineGuid") {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func runCommand(name string, args ...string) (string, error) {
	// Bounded so a wedged helper cannot hang an application's startup.
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return "", err
		}
		return stdout.String(), nil
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return "", errors.New("licencly: machine id command timed out")
	}
}

// virtualPrefixes are interfaces created by software rather than shipped with
// the machine. Their addresses come and go with a container or a VPN, so a
// fingerprint built on one is not stable.
var virtualPrefixes = []string{
	"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "vnic",
	"tun", "tap", "utun", "wg", "tailscale", "zt", "ham", "lo",
}

// stableMAC returns the hardware address of the most plausible physical
// interface, chosen deterministically.
//
// Interfaces that are merely down are still considered: a laptop with the
// ethernet cable out must not get a different fingerprint from the same laptop
// plugged in.
func stableMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	var candidates []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		// Bit 0x02 of the first octet marks a locally administered address:
		// randomised Wi-Fi, container bridges and most virtual adapters. Never
		// stable, so never a fingerprint.
		if iface.HardwareAddr[0]&0x02 != 0 {
			continue
		}
		if isVirtualName(iface.Name) {
			continue
		}
		candidates = append(candidates, iface)
	}
	if len(candidates) == 0 {
		return ""
	}

	// Sorted by name so a machine with two NICs answers the same way every
	// launch, whatever order the kernel happened to enumerate them in.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return candidates[0].HardwareAddr.String()
}

func isVirtualName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
