//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func decodeRules(t *testing.T, body string) []map[string]any {
	t.Helper()
	var rules []map[string]any
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&rules); err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestPolicyPreflightHandlesNumericStringsAndRejectsSelectors(t *testing.T) {
	for _, body := range []string{`[{"priority":0,"src":"all","table":"255","protocol":"2"},{"priority":32766,"table":"254"}]`, `[{"priority":0,"table":255},{"priority":32766,"table":254},{"priority":32767,"table":253}]`, `[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`} {
		if err := validateRules(decodeRules(t, body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`[{"priority":0,"table":"255"},{"priority":32766,"table":"254","fwmark":1}]`, `[{"priority":0,"table":"255"},{"priority":32766,"table":"254","src":"192.0.2.1"}]`, `[{"priority":0,"table":255},{"priority":10,"table":254}]`, `[{"priority":0,"table":255},{"priority":32766,"table":254.0}]`, `[{"priority":0,"table":255},{"priority":32766,"table":true}]`} {
		if err := validateRules(decodeRules(t, body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func fixtureHost(t *testing.T) *Host {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return &Host{Dir: dir, stateUID: uint32(os.Getuid())}
}

func TestWriteAheadRollbackAndPrivateState(t *testing.T) {
	h := fixtureHost(t)
	st := &state{Owner: "usque-native-v1"}
	mutations := 0
	h.Exec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "rule add") {
			mutations++
			var recorded state
			if err := h.readJSON("session.json", &recorded); err != nil || len(recorded.Undo) != 1 {
				t.Fatalf("intent missing before mutation: %v %+v", err, recorded)
			}
			return nil, errors.New("injected add failure")
		}
		if strings.Contains(strings.Join(args, " "), "rule show") {
			return []byte(`[]`), nil
		}
		t.Fatalf("unexpected cleanup command: %s %v", name, args)
		return nil, nil
	}
	err := h.addRule(context.Background(), st, 6, 18051, "to", team6.String(), "lookup", "main")
	if err == nil || mutations != 1 {
		t.Fatal(err, mutations)
	}
	info, err := os.Stat(filepath.Join(h.Dir, "session.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	if err = h.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = h.Cleanup(context.Background()); err != nil {
		t.Fatal("cleanup is not idempotent", err)
	}
}

func TestCleanupRejectsUnrecognizedCommands(t *testing.T) {
	h := fixtureHost(t)
	h.Exec = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("executed an unrecognized state action")
		return nil, nil
	}
	st := &state{Owner: "usque-native-v1", Undo: []action{{Kind: "rule", Family: 4, Priority: 32766, Selectors: []string{"lookup", "main"}}}}
	if err := h.save(st); err != nil {
		t.Fatal(err)
	}
	if err := h.Cleanup(context.Background()); err == nil {
		t.Fatal("unsafe cleanup was accepted")
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "session.json")); err != nil {
		t.Fatal("failed cleanup state was lost")
	}
}

func TestConfigAndCachePreserveOriginalCredentials(t *testing.T) {
	h := fixtureHost(t)
	path := filepath.Join(t.TempDir(), "original.json")
	body := []byte(`{"endpoint_v4":"162.159.197.2","endpoint_v6":"2606:4700:102::2","ipv4":"172.16.0.2","ipv6":"fd42::2","private_key":"secret-device-key","endpoint_pub_key":"original-pin","access_token":"secret-token"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, read, err := ReadConfig(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	targets, err := BuildTargets(cfg.Endpoint4, cfg.Endpoint6, []int{500})
	if err != nil {
		t.Fatal(err)
	}
	registration := digest(read)
	c := cache{Target: targets[0], Network: "network-hash", Registration: registration, At: time.Now()}
	if err = h.writeJSON("last-endpoint.json", c); err != nil {
		t.Fatal(err)
	}
	if got := h.cacheTarget(c.Network, registration, targets); got != c.Target {
		t.Fatal(got)
	}
	if got := h.cacheTarget("different-network", registration, targets); got.Valid() {
		t.Fatal("cross-network cached target accepted")
	}
	if got := h.cacheTarget(c.Network, "changed-registration", targets); got.Valid() {
		t.Fatal("cross-registration cached target accepted")
	}
	saved, _ := os.ReadFile(path)
	if !bytes.Equal(saved, body) {
		t.Fatal("original configuration changed")
	}
	stored, _ := os.ReadFile(filepath.Join(h.Dir, "last-endpoint.json"))
	for _, secret := range []string{"secret-device-key", "secret-token", "original-pin"} {
		if bytes.Contains(stored, []byte(secret)) {
			t.Fatal("cache retained secret", secret)
		}
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ReadConfig(path, os.Getuid()); err == nil {
		t.Fatal("accepted world-readable registration")
	}
}

func TestPhysicalIPv6RequiresPublicSourceAndRejectsTunnel(t *testing.T) {
	h := fixtureHost(t)
	for _, body := range []string{`[{"dev":"wlan0","prefsrc":"fe80::1"}]`, `[{"dev":"wlan0","prefsrc":"fd42::1"}]`, `[{"dev":"usque0","prefsrc":"2001:db8::1"}]`, `[{"dev":"wlan0"}]`} {
		h.Exec = func(context.Context, string, ...string) ([]byte, error) { return []byte(body), nil }
		if _, err := h.Route(context.Background(), team6.Addr()); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	h.Exec = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`[{"dev":"wlan0","prefsrc":"2001:db8::1","gateway":"fe80::1"}]`), nil
	}
	if _, err := h.Route(context.Background(), team6.Addr()); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdNotFoundAndNoAutostartArguments(t *testing.T) {
	h := fixtureHost(t)
	h.Exec = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("LoadState=not-found\nActiveState=inactive\n"), errors.New("unit absent")
	}
	if _, err := h.UnitState(context.Background()); err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions()
	o.Executable = "/usr/local/bin/usque"
	o.ConfigPath = "/home/example/.config/usque/config.json"
	args := StartArgs(o)
	s := strings.Join(args, " ")
	for _, want := range []string{"--collect", "--expand-environment=no", "Restart=no", "Type=notify", "ExecStopPost=/usr/local/bin/usque _session-cleanup", "--family prefer6"} {
		if !strings.Contains(s, want) {
			t.Error("missing", want)
		}
	}
	for _, bad := range []string{"--on-boot", "enable", "--insecure", "--http2"} {
		if strings.Contains(s, bad) {
			t.Error("unexpected", bad)
		}
	}
	i := slicesIndex(args, "--config")
	if i < 0 || !reflect.DeepEqual(args[i:i+2], []string{"--config", o.ConfigPath}) {
		t.Fatal("config path was not passed as a separate argument")
	}
}

func slicesIndex(s []string, x string) int {
	for i, v := range s {
		if v == x {
			return i
		}
	}
	return -1
}
