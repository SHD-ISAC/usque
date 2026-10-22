package scout

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestSelectedConfigPreservesAllCredentialsAndUnknownFields(t *testing.T) {
	// Deliberately fake values, never usable registration credentials.
	original := []byte(`{"private_key":"fake-private","access_token":"fake-token","id":"fake-device","endpoint_pub_key":"original-pin","endpoint_v4":"162.159.197.2","endpoint_v6":"2606:4700:102::2","endpoint_h2_v4":"162.159.198.2","future":{"preserve":true}}`)
	before := bytes.Clone(original)
	for _, target := range []Target{{netip.MustParseAddrPort("162.159.197.1:8443"), QUIC}, {netip.MustParseAddrPort("[2606:4700:102::1]:443"), HTTP2}} {
		body, err := SelectedConfig(original, target)
		if err != nil {
			t.Fatal(err)
		}
		var got, want map[string]json.RawMessage
		_ = json.Unmarshal(body, &got)
		_ = json.Unmarshal(original, &want)
		for _, key := range []string{"private_key", "access_token", "id", "endpoint_pub_key", "future"} {
			var a, b any
			_ = json.Unmarshal(got[key], &a)
			_ = json.Unmarshal(want[key], &b)
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			if !bytes.Equal(x, y) {
				t.Fatalf("changed %s", key)
			}
		}
		if !bytes.Equal(original, before) {
			t.Fatal("input bytes were modified")
		}
		field := "endpoint_v4"
		if target.Transport == HTTP2 {
			field = "endpoint_h2_v6"
		}
		var endpoint string
		_ = json.Unmarshal(got[field], &endpoint)
		if endpoint != target.Endpoint.Addr().String() {
			t.Fatalf("wrong field: %s=%s", field, endpoint)
		}
	}
}

func TestWriteNewFileIsPrivateAndRefusesOverwriteAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "copy.json")
	if err := WriteNewFile(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := WriteNewFile(path, []byte("replacement")); err == nil {
		t.Fatal("overwrote existing file")
	}
	body, _ := os.ReadFile(path)
	if string(body) != "original" {
		t.Fatal("original changed")
	}
	for _, target := range []string{path, filepath.Join(dir, "missing.json")} {
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := WriteNewFile(link, []byte("secret")); err == nil {
			t.Fatal("followed symlink")
		}
		_ = os.Remove(link)
	}
}
