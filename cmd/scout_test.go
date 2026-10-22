package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Diniboy1123/usque/scout"
	"github.com/spf13/cobra"
)

func TestScoutRefusesExistingOutputBeforeProbing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "original.json")
	body := []byte(`{"private_key":"fake-private","endpoint_pub_key":"original-pin","access_token":"fake-token"}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	root := &cobra.Command{Use: "usque"}
	root.PersistentFlags().String("config", path, "")
	root.AddCommand(newScoutCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"scout", "--write-config", path})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "will not overwrite") {
		t.Fatalf("expected early refusal: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatal("original configuration changed")
	}
	if strings.Contains(out.String(), "fake-private") || strings.Contains(out.String(), "fake-token") {
		t.Fatal("credentials in output")
	}
}

func TestScoutHelpExplainsReadOnlyDefaults(t *testing.T) {
	cmd := newScoutCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"warpscout", "--write-config", "--output-report", "--profile", "--transport", "--attempts"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %s", want)
		}
	}
}

func TestScoutFishQuoting(t *testing.T) {
	if got := scoutShellQuote("/tmp/Freeman's\\config.json"); got != "'/tmp/Freeman\\'s\\\\config.json'" {
		t.Fatal(got)
	}
}

func TestScoutDisplaysFailureStageAndTraceFallback(t *testing.T) {
	r := scout.Result{Attempts: []scout.Attempt{{Status: "http-error", Stage: "probe", Error: "metadata server responded with 403"}}}
	status, stage, _, detail := scoutResultDetails(r)
	if status != "http-error" || stage != "probe" || detail != "metadata server responded with 403" {
		t.Fatalf("diagnostic hidden: %s %s %s", status, stage, detail)
	}
	r.Successes = 1
	r.Location = &scout.Measurement{Source: "https://www.cloudflare.com/cdn-cgi/trace", MetadataError: "metadata server responded with 403"}
	status, stage, check, detail := scoutResultDetails(r)
	if status != "ok" || stage != "probe" || check != "trace" || detail == "" {
		t.Fatal("fallback not shown")
	}
	if !newScoutCommand().SilenceErrors {
		t.Fatal("Cobra will duplicate main's error")
	}
}
