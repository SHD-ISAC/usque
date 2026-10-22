//go:build linux

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/scout"
	"github.com/Diniboy1123/usque/session"
	"github.com/spf13/cobra"
)

func invokingUID() (int, error) {
	uid := os.Getuid()
	if uid == 0 && os.Getenv("SUDO_UID") != "" {
		n, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid SUDO_UID")
		}
		uid = int(n)
	}
	return uid, nil
}

func sessionConfigPath(cmd *cobra.Command, uid int) (string, error) {
	path, _ := cmd.Flags().GetString("config")
	if !cmd.Flags().Changed("config") && !rootCmd.PersistentFlags().Changed("config") {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return "", err
		}
		path = filepath.Join(u.HomeDir, ".config/usque/config.json")
	}
	return filepath.Abs(path)
}

func sessionFlags(cmd *cobra.Command, o *session.Options) {
	f := cmd.Flags()
	f.StringVar(&o.Family, "family", o.Family, "Outer endpoint preference: prefer6, 4 or 6 (inner traffic stays dual-stack)")
	f.IntSliceVar(&o.Ports, "ports", o.Ports, "Ordered QUIC endpoint ports; automatically try alternatives")
	f.DurationVar(&o.ProbeTimeout, "probe-timeout", o.ProbeTimeout, "Deadline for each full pinned CONNECT-IP + tunneled HTTPS probe")
	f.DurationVar(&o.FamilyBudget, "family-budget", o.FamilyBudget, "Selection budget per address family before fallback")
	f.DurationVar(&o.HealthInterval, "health-interval", o.HealthInterval, "Interval between native UDP DNS and dual-stack HTTPS checks")
	f.DurationVar(&o.IPv6Retry, "ipv6-retry", o.IPv6Retry, "While using IPv4, retry verified IPv6 after this interval")
	f.StringVar(&o.BypassCN, "bypass-cn", o.BypassCN, "Optional CN bypass: off, ip, domain or both; flag alone means both")
	f.Lookup("bypass-cn").NoOptDefVal = "both"
	f.StringVar(&o.GeoIPFile, "geoip-file", "", "Existing Xray geoip.dat (auto-detect standard asset directories)")
	f.StringVar(&o.GeoSiteFile, "geosite-file", "", "Existing Xray geosite.dat (auto-detect standard asset directories)")
	f.StringSliceVar(&o.CNDNS, "cn-dns", o.CNDNS, "Domestic DNS literal IP[:port] servers, queried through the physical network")
}

func prepareCNOptions(o *session.Options) error {
	if o.BypassCN == "off" || o.BypassCN == "" {
		return nil
	}
	u, err := user.LookupId(strconv.Itoa(o.OwnerUID))
	if err != nil {
		return err
	}
	if o.BypassCN == "ip" || o.BypassCN == "both" {
		o.GeoIPFile, err = session.FindGeoData("geoip.dat", o.GeoIPFile, u.HomeDir)
		if err != nil {
			return err
		}
	}
	if o.BypassCN == "domain" || o.BypassCN == "both" {
		o.GeoSiteFile, err = session.FindGeoData("geosite.dat", o.GeoSiteFile, u.HomeDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func upFlagArgs(cmd *cobra.Command) []string {
	var args []string
	for _, name := range []string{"family", "ports", "probe-timeout", "family-budget", "health-interval", "ipv6-retry", "bypass-cn", "geoip-file", "geosite-file", "cn-dns"} {
		f := cmd.Flags().Lookup(name)
		value := f.Value.String()
		if slice, ok := f.Value.(interface{ GetSlice() []string }); ok {
			value = strings.Join(slice.GetSlice(), ",")
		}
		// Equals also preserves NoOptDefVal and IPv6 brackets through sudo.
		args = append(args, "--"+name+"="+value)
	}
	return args
}

func elevateSession(exe string, args []string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return syscall.Exec("/usr/bin/sudo", append([]string{"sudo", "--", exe}, args...), os.Environ())
}

func newUpCommand() *cobra.Command {
	o := session.DefaultOptions()
	var plan bool
	cmd := &cobra.Command{Use: "up", Short: "Start an adaptive dual-stack system TUN on demand (Linux)", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			o.OwnerUID, err = invokingUID()
			if err != nil {
				return err
			}
			o.ConfigPath, err = sessionConfigPath(cmd, o.OwnerUID)
			if err != nil {
				return err
			}
			o.Executable, err = os.Executable()
			if err != nil {
				return err
			}
			if err = o.Validate(); err != nil {
				return err
			}
			if err = prepareCNOptions(&o); err != nil {
				return err
			}
			// Resolve paths before sudo sanitizes XRAY_LOCATION_ASSET.
			_ = cmd.Flags().Set("geoip-file", o.GeoIPFile)
			_ = cmd.Flags().Set("geosite-file", o.GeoSiteFile)
			if err = session.TrustedExecutable(o.Executable); err != nil {
				return err
			}
			if plan {
				cfg, _, err := session.ReadConfig(o.ConfigPath, o.OwnerUID)
				if err != nil {
					return err
				}
				h := session.NewHost()
				if err = h.Preflight(cmd.Context(), cfg); err != nil {
					return err
				}
				data, err := session.LoadCNData(o.BypassCN, o.GeoIPFile, o.GeoSiteFile)
				if err != nil {
					return err
				}
				if data != nil {
					if err = h.CheckCNTable(cmd.Context()); err != nil {
						return err
					}
				}
				targets, err := session.BuildTargets(cfg.Endpoint4, cfg.Endpoint6, o.Ports)
				if err != nil {
					return err
				}
				// Show only endpoint choices and policy. Never serialize cfg.
				prefixes, domains := 0, 0
				if data != nil {
					prefixes, domains = len(data.Prefixes), data.DomainCount()
				}
				body, err := json.MarshalIndent(map[string]any{"config": o.ConfigPath, "family": o.Family, "interface": session.Interface, "targets": targets, "original_pin": true, "autostart": false, "bypass_cn": o.BypassCN, "geoip_file": o.GeoIPFile, "geosite_file": o.GeoSiteFile, "cn_prefixes": prefixes, "cn_domains": domains}, "", "  ")
				if err != nil {
					return err
				}
				cmd.Println(string(body))
				return nil
			}
			if os.Geteuid() != 0 {
				args := []string{"up", "--config", o.ConfigPath}
				args = append(args, upFlagArgs(cmd)...)
				return elevateSession(o.Executable, args)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return session.NewHost().Start(ctx, o)
		},
	}
	sessionFlags(cmd, &o)
	cmd.Flags().BoolVar(&plan, "plan", false, "Read-only local preflight and endpoint plan; does not probe or change routes")
	return cmd
}

func newSessionRunCommand() *cobra.Command {
	o := session.DefaultOptions()
	cmd := &cobra.Command{Use: "_session-run", Hidden: true, Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 || os.Getenv("NOTIFY_SOCKET") == "" {
				return fmt.Errorf("internal runner requires the usque up systemd unit")
			}
			var err error
			o.Executable, err = os.Executable()
			if err != nil {
				return err
			}
			o.ConfigPath, err = filepath.Abs(mustConfigPath(cmd))
			if err != nil {
				return err
			}
			_, raw, err := session.ReadConfig(o.ConfigPath, o.OwnerUID)
			if err != nil {
				return err
			}
			var cfg config.Config
			if err = json.Unmarshal(raw, &cfg); err != nil {
				return err
			}
			engine, err := scout.NewEngine(cfg, scout.DefaultSNI("team"), 0)
			if err != nil {
				return err
			}
			hash := sha256.Sum256(raw)
			o.RegistrationDigest = hex.EncodeToString(hash[:])
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return session.NewHost().Run(ctx, o, func(ctx context.Context, t session.Target) error {
				_, err := engine.Probe(ctx, scout.Target{Endpoint: t.AddrPort(), Transport: scout.QUIC})
				return err
			})
		},
	}
	sessionFlags(cmd, &o)
	cmd.Flags().IntVar(&o.OwnerUID, "owner-uid", 0, "Original config owner UID")
	cmd.Flags().IntVar(&o.LauncherPID, "launcher-pid", 0, "Launching up process to exclude from preflight")
	return cmd
}

func mustConfigPath(cmd *cobra.Command) string {
	path, _ := cmd.Flags().GetString("config")
	return path
}

func newDownCommand() *cobra.Command {
	return &cobra.Command{Use: "down", Short: "Stop the manual system TUN and restore its routes/DNS", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err = session.TrustedExecutable(exe); err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			return elevateSession(exe, []string{"down"})
		}
		if err = session.NewHost().Stop(cmd.Context()); err != nil {
			return err
		}
		cmd.Println("Usque session stopped; its routing and DNS have been removed.")
		return nil
	}}
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show the manual TUN service and selected endpoint", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		data, err := session.NewHost().UnitState(cmd.Context())
		if err == nil {
			cmd.Print(data)
		}
		return err
	}}
}

func newCleanupCommand() *cobra.Command {
	return &cobra.Command{Use: "_session-cleanup", Hidden: true, Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("cleanup requires root")
		}
		return session.NewHost().Cleanup(cmd.Context())
	}}
}

func newCheckCommand() *cobra.Command {
	var duration, interval time.Duration
	cmd := &cobra.Command{Use: "check", Short: "Check native TUN UDP DNS and IPv4/IPv6 HTTPS", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		if duration < 0 || duration > 24*time.Hour || interval < time.Second || interval > time.Hour {
			return fmt.Errorf("duration must be 0..24h and interval 1s..1h")
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			if err = session.TrustedExecutable(exe); err != nil {
				return err
			}
			return elevateSession(exe, []string{"check", "--duration", duration.String(), "--interval", interval.String()})
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		deadline := time.Now().Add(duration)
		checks, passed := 0, 0
		for {
			attempt, cancel := context.WithTimeout(ctx, 25*time.Second)
			health, e := session.Check(attempt, session.Interface)
			cancel()
			checks++
			if e == nil {
				passed++
				for _, h := range health {
					cmd.Printf("IPv%d UDP DNS + HTTPS: warp=%s colo=%s elapsed=%dms\n", h.Family, h.Warp, h.Colo, h.MS)
				}
			} else {
				cmd.PrintErrln(e)
			}
			if duration == 0 || time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			timer := time.NewTimer(min(interval, time.Until(deadline)))
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			if ctx.Err() != nil || time.Now().After(deadline) {
				break
			}
		}
		cmd.Printf("Dual-stack checks passed: %d/%d\n", passed, checks)
		if passed != checks {
			return fmt.Errorf("one or more native TUN checks failed")
		}
		return ctx.Err()
	}}
	cmd.Flags().DurationVar(&duration, "duration", 0, "Repeat checks for this long; 0 checks once")
	cmd.Flags().DurationVar(&interval, "interval", 10*time.Second, "Delay between check rounds")
	return cmd
}

func init() {
	rootCmd.AddCommand(newUpCommand(), newDownCommand(), newStatusCommand(), newCheckCommand(), newSessionRunCommand(), newCleanupCommand(), newLegacyCleanupCommand())
}

func newLegacyCleanupCommand() *cobra.Command {
	var plan bool
	cmd := &cobra.Command{Use: "cleanup-legacy", Short: "Remove the verified old Python TUN helper and its command aliases", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		if !plan && os.Geteuid() != 0 {
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if err = session.TrustedExecutable(exe); err != nil {
				return err
			}
			return elevateSession(exe, []string{"cleanup-legacy"})
		}
		files, err := session.CleanupLegacy(cmd.Context(), plan)
		if err != nil {
			return err
		}
		for _, file := range files {
			if plan {
				cmd.Println("Would remove:", file)
			} else {
				cmd.Println("Removed:", file)
			}
		}
		if len(files) == 0 {
			cmd.Println("No verified legacy helper files remain.")
		}
		return nil
	}}
	cmd.Flags().BoolVar(&plan, "plan", false, "Read-only inspection of known legacy files")
	return cmd
}
