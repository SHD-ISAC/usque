//go:build linux

package session

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyInspectionRefusesUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "usque-session")
	body := []byte("#!/usr/bin/python3\n# fixture\n")
	if err := os.WriteFile(helper, body, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"usque-up", "usque-down"} {
		if err := os.Symlink("usque-session", filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	files, err := inspectLegacyHash(dir, digest(body))
	if err != nil || len(files) != 3 {
		t.Fatal(files, err)
	}
	if _, err = inspectLegacy(dir); err == nil {
		t.Fatal("unverified script accepted by real hash guard")
	}
	if err = os.Remove(filepath.Join(dir, "usque-up")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "usque-up"), []byte("unrelated command"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectLegacyHash(dir, digest(body)); err == nil {
		t.Fatal("regular command accepted as an old symlink")
	}
	if _, err = os.Stat(helper); err != nil {
		t.Fatal("inspection modified files")
	}
}

func TestActiveConnectionKeepsExpiredDNSRoute(t *testing.T) {
	r := routerFixture()
	ip := netip.MustParseAddr("104.16.1.2")
	r.learned[ip] = time.Now().Add(-time.Minute)
	r.active = func() map[netip.Addr]bool { return map[netip.Addr]bool{ip: true} }
	if err := r.expire(time.Now()); err != nil || len(r.learned) != 1 {
		t.Fatal("active connection route expired", err)
	}
	r.active = func() map[netip.Addr]bool { return nil }
	if err := r.expire(time.Now().Add(time.Minute)); err != nil || len(r.learned) != 0 {
		t.Fatal("idle expired route retained", err)
	}
	for input, want := range map[string]string{"02011068:01BB": "104.16.1.2", "00000000000000000000000001000000:0035": "::1"} {
		got, ok := procAddress(input)
		if !ok || got.String() != want {
			t.Fatal(input, got, ok)
		}
	}
}
