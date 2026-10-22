//go:build linux

package cmd

import (
	"net"
	"reflect"
	"testing"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

func TestNativeEndpointOverridePreservesRegistration(t *testing.T) {
	original := config.AppConfig
	defer func() { config.AppConfig = original }()
	config.AppConfig = config.Config{EndpointV4: "162.159.197.2", EndpointV6: "", EndpointPubKey: "original-pin", PrivateKey: "existing-device-key", AccessToken: "existing-token"}
	before := config.AppConfig
	addr, err := nativeEndpoint(false, true, 4500, "2606:4700:102::1")
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "[2606:4700:102::1]:4500" {
		t.Fatal(addr)
	}
	if _, ok := addr.(*net.UDPAddr); !ok {
		t.Fatal("wrong transport")
	}
	if !reflect.DeepEqual(config.AppConfig, before) {
		t.Fatal("runtime override changed original configuration")
	}
	for _, bad := range []struct {
		ip   string
		v6   bool
		port int
	}{{"2606:4700:102::1", false, 500}, {"162.159.197.2", true, 500}, {"::ffff:162.159.197.2", true, 500}, {"2606:4700:102::1%wlan0", true, 500}, {"example.com", false, 500}, {"162.159.197.2", false, 65536}} {
		if _, err := nativeEndpoint(false, bad.v6, bad.port, bad.ip); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestSessionCommandsDoNotRunRegistrationPreload(t *testing.T) {
	for _, cmd := range []*cobra.Command{newUpCommand(), newDownCommand(), newStatusCommand(), newCheckCommand(), newSessionRunCommand(), newCleanupCommand(), newLegacyCleanupCommand()} {
		if cmd.PersistentPreRun == nil {
			t.Errorf("%s inherits unrelated config preload", cmd.Name())
		}
		if cmd.RunE == nil {
			t.Errorf("%s has no error-returning handler", cmd.Name())
		}
	}
}

func TestCNFlagsSurvivePrivilegeForwarding(t *testing.T) {
	cmd := newUpCommand()
	if err := cmd.ParseFlags([]string{"--bypass-cn", "--cn-dns=[2400:3200::1]:53", "--ports=500,4500", "--geoip-file=/tmp/path with spaces/geoip.dat"}); err != nil {
		t.Fatal(err)
	}
	other := newUpCommand()
	if err := other.ParseFlags(upFlagArgs(cmd)); err != nil {
		t.Fatal(err)
	}
	mode, _ := other.Flags().GetString("bypass-cn")
	servers, _ := other.Flags().GetStringSlice("cn-dns")
	ports, _ := other.Flags().GetIntSlice("ports")
	path, _ := other.Flags().GetString("geoip-file")
	if mode != "both" || !reflect.DeepEqual(servers, []string{"[2400:3200::1]:53"}) || !reflect.DeepEqual(ports, []int{500, 4500}) || path != "/tmp/path with spaces/geoip.dat" {
		t.Fatal(mode, servers, ports, path)
	}
}
