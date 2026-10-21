package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveConfigUsesReceiver(t *testing.T) {
	oldGlobal := AppConfig
	t.Cleanup(func() { AppConfig = oldGlobal })
	AppConfig = Config{ID: "global"}

	cfg := Config{ID: "receiver", AccessToken: "secret"}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != cfg.ID || got.AccessToken != cfg.AccessToken {
		t.Fatalf("saved config = %#v, want receiver %#v", got, cfg)
	}
}

func TestSaveConfigRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits consistently")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Config{ID: "test", AccessToken: "secret"}
	if err := cfg.SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config permissions = %04o, want 0600", got)
	}
}
