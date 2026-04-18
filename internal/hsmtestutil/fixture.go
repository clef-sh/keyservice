//go:build integration

// Package hsmtestutil provides test fixtures for integration tests that
// need a real PKCS#11 HSM. Only compiled under the `integration` build tag.
package hsmtestutil

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Fixture is a provisioned SoftHSM2 token with an RSA-2048 wrap keypair,
// suitable for RSA-OAEP round-trip tests.
type Fixture struct {
	ModulePath string // absolute path to libsofthsm2.so/.dylib
	SlotID     uint   // PKCS#11 slot ID of the initialized token
	KeyLabel   string // CKA_LABEL of the RSA keypair
	PIN        string // User PIN for C_Login
}

// SoftHSM2 provisions a throwaway SoftHSM2 token in a per-test temp dir
// and generates an RSA-2048 keypair on it. The token is cleaned up by
// t.TempDir's lifecycle.
//
// Skips the test if libsofthsm2.so or the softhsm2-util / pkcs11-tool
// binaries are not available on the host.
func SoftHSM2(t *testing.T) Fixture {
	t.Helper()

	modulePath := findSoftHSM2Module(t)
	requireBinary(t, "softhsm2-util")
	requireBinary(t, "pkcs11-tool")

	tokenDir := t.TempDir()
	confPath := filepath.Join(tokenDir, "softhsm2.conf")
	conf := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokenDir,
	)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const (
		tokenLabel = "clef-test"
		userPIN    = "1234"
		soPIN      = "1234"
		keyLabel   = "clef-dek-wrapper"
	)

	run(t, "softhsm2-util",
		"--init-token", "--free",
		"--label", tokenLabel,
		"--pin", userPIN,
		"--so-pin", soPIN,
	)

	slotID := firstSlotForLabel(t, tokenLabel)

	run(t, "pkcs11-tool",
		"--module", modulePath,
		"--login", "--pin", userPIN,
		"--slot", fmt.Sprint(slotID),
		"--keypairgen", "--key-type", "rsa:2048",
		"--label", keyLabel,
		"--id", "01",
	)

	return Fixture{
		ModulePath: modulePath,
		SlotID:     slotID,
		KeyLabel:   keyLabel,
		PIN:        userPIN,
	}
}

// PKCS11URI returns the pkcs11: URI for this fixture's wrap keypair,
// pinning hash=sha1 to work around SoftHSM2 2.7's broken SHA-256 OAEP.
func (f Fixture) PKCS11URI() string {
	return fmt.Sprintf("pkcs11:slot=%d;label=%s;hash=sha1", f.SlotID, f.KeyLabel)
}

func findSoftHSM2Module(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("libsofthsm2.so not found; checked: %s", strings.Join(candidates, ", "))
	return ""
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not on PATH: %v", name, err)
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\nstdout: %s\nstderr: %s",
			name, strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

var slotLineRE = regexp.MustCompile(`(?m)^Slot\s+(\d+)`)

// firstSlotForLabel returns the slot ID of the first SoftHSM2 token whose
// Label matches the given value.
func firstSlotForLabel(t *testing.T, label string) uint {
	t.Helper()
	out := run(t, "softhsm2-util", "--show-slots")

	slotIdxs := slotLineRE.FindAllStringSubmatchIndex(out, -1)
	for i, match := range slotIdxs {
		start := match[0]
		end := len(out)
		if i+1 < len(slotIdxs) {
			end = slotIdxs[i+1][0]
		}
		block := out[start:end]
		if !strings.Contains(block, "Label:            "+label) &&
			!strings.Contains(block, "Label: "+label) {
			continue
		}
		var slotID uint
		if _, err := fmt.Sscanf(out[match[2]:match[3]], "%d", &slotID); err != nil {
			t.Fatalf("parse slot id %q: %v", out[match[2]:match[3]], err)
		}
		return slotID
	}
	t.Fatalf("no slot with label %q found in:\n%s", label, out)
	return 0
}
