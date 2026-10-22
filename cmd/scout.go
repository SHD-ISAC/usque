package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/scout"
	"github.com/spf13/cobra"
)

type scoutReport struct {
	Schema         int            `json:"schema"`
	CreatedAt      time.Time      `json:"created_at"`
	Profile        string         `json:"profile"`
	SNI            string         `json:"sni"`
	PlannedTargets int            `json:"planned_targets"`
	Cancelled      bool           `json:"cancelled"`
	Results        []scout.Result `json:"results"`
}

func newScoutCommand() *cobra.Command {
	var targets scout.TargetOptions
	var options scout.Options
	var sni, reportPath, copyPath string
	var initialSize uint16
	cmd := &cobra.Command{
		Use:          "scout",
		Short:        "Find usable MASQUE endpoints with an existing registration",
		Long:         "warpscout-derived MASQUE probing for existing Usque Team or consumer registrations.\nAuthenticates with the original pinned endpoint key, then fetches Cloudflare metadata\nover the userspace tunnel. Does not register, change routes or overwrite configuration.\nDials endpoint IPs directly; environment proxies are ignored.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			for _, output := range []string{reportPath, copyPath} {
				if output == "" {
					continue
				}
				if _, err := os.Lstat(output); err == nil {
					return fmt.Errorf("output already exists (will not overwrite): %s", output)
				} else if !os.IsNotExist(err) {
					return err
				}
			}
			path, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			original, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read existing configuration: %w", err)
			}
			var cfg config.Config
			if err := json.Unmarshal(original, &cfg); err != nil {
				return fmt.Errorf("invalid existing configuration: %w", err)
			}
			targets.Configured = []string{cfg.EndpointV4, cfg.EndpointV6, cfg.EndpointH2V4, cfg.EndpointH2V6}
			candidates, err := scout.BuildTargets(targets)
			if err != nil {
				return err
			}
			name := sni
			if name == "" {
				name = scout.DefaultSNI(targets.Profile)
			}
			engine, err := scout.NewEngine(cfg, name, initialSize)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			fmt.Fprintf(cmd.ErrOrStderr(), "Probing %d targets; profile=%s, SNI=%s, attempts=%d, workers=%d, timeout=%s per full attempt\nOriginal public-key pin enforced. Direct endpoint dialing; no API registration or relay.\n", len(candidates), targets.Profile, name, options.Attempts, options.Workers, options.Timeout)
			completed := 0
			results, scanErr := scout.Scan(ctx, candidates, options, engine.Probe, func(r scout.Result) {
				completed++
				status := "ok"
				if r.Successes == 0 && len(r.Attempts) > 0 {
					status = r.Attempts[len(r.Attempts)-1].Status
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "[%d/%d] %s %-5s %d/%d %s\n", completed, len(candidates), r.Target.Endpoint, r.Target.Transport, r.Successes, len(r.Attempts), status)
			})
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ENDPOINT\tTRANSPORT\tOK/TRIES\tMEDIAN ms\tCOUNTRY\tCOLO\tSTATUS")
			for _, r := range results {
				country, colo, status := "-", "-", "ok"
				if r.Location != nil {
					country, colo = r.Location.Country, r.Location.Colo
				}
				if r.Successes == 0 && len(r.Attempts) > 0 {
					status = r.Attempts[len(r.Attempts)-1].Status
				}
				fmt.Fprintf(w, "%s\t%s\t%d/%d\t%.1f\t%s\t%s\t%s\n", r.Target.Endpoint, r.Target.Transport, r.Successes, len(r.Attempts), r.MedianMS, country, colo, status)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			// Reports contain probe results only, never the configuration, device
			// ID, private key, access token or full peer public key.
			if reportPath != "" {
				body, err := json.MarshalIndent(scoutReport{1, time.Now().UTC(), targets.Profile, name, len(candidates), scanErr != nil, results}, "", "  ")
				if err != nil {
					return err
				}
				if err := scout.WriteNewFile(reportPath, append(body, '\n')); err != nil {
					return fmt.Errorf("write new report: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Report: %s\n", reportPath)
			}
			if scanErr != nil {
				return scanErr
			}
			if len(results) == 0 || results[0].Successes == 0 {
				return fmt.Errorf("no candidate passed pinned CONNECT-IP and tunneled HTTPS; inspect --output-report for individual failures; no config copy created")
			}
			best := results[0].Target
			fmt.Fprintf(cmd.OutOrStdout(), "Best verified candidate: %s %s\n", best.Transport, best.Endpoint)
			if copyPath != "" {
				body, err := scout.SelectedConfig(original, best)
				if err != nil {
					return err
				}
				if err := scout.WriteNewFile(copyPath, body); err != nil {
					return fmt.Errorf("write new config copy: %w", err)
				}
				flags := ""
				if best.Transport == scout.HTTP2 {
					flags += " --http2"
				}
				if best.Endpoint.Addr().Is6() {
					flags += " -6"
				}
				if initialSize != 0 {
					flags += fmt.Sprintf(" -i %d", initialSize)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "New config copy (0600): %s\nTest with:\nenv -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy usque -c %s socks -b 127.0.0.1 -p 10810 -s %s -P %d%s --always-reconnect\n", copyPath, scoutShellQuote(copyPath), scoutShellQuote(name), best.Endpoint.Port(), flags)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "To save a candidate, run scout with --write-config NEWFILE. The original config is never overwritten.")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&targets.Profile, "profile", "team", "Endpoint profile: team or consumer (must match the registration)")
	f.StringVar(&targets.Family, "family", "4", "Outer endpoint address family: 4, 6 or both")
	f.StringVar(&targets.Transport, "transport", "both", "Transport: quic, http2 or both")
	f.StringSliceVar(&targets.Endpoints, "endpoints", nil, "Comma-separated literal endpoint IPs or small CIDRs; overrides defaults (max 256 addresses)")
	f.IntSliceVar(&targets.Ports, "ports", nil, "Override ports for selected transports; defaults to 7 QUIC ports and TCP 443")
	f.StringVarP(&sni, "sni-address", "s", "", "SNI override; defaults to the selected profile's MASQUE hostname")
	f.IntVarP(&options.Workers, "workers", "w", 2, "Concurrent probes (1..8)")
	f.IntVar(&options.Attempts, "attempts", 3, "Independent attempts per endpoint/transport/port (1..10)")
	f.DurationVar(&options.Timeout, "timeout", 10*time.Second, "Timeout for each complete CONNECT-IP and tunneled HTTPS attempt (1s..1m)")
	f.Uint16VarP(&initialSize, "initial-packet-size", "i", 0, "Initial QUIC packet size; 0 uses Usque's normal PMTU discovery")
	f.StringVar(&reportPath, "output-report", "", "Write a new JSON report (0600); existing files are refused")
	f.StringVar(&copyPath, "write-config", "", "Write a separate config for the best verified endpoint (0600); existing files are refused")
	return cmd
}

// Single quotes and backslashes are escaped for Fish. No
// credentials are placed in the suggested command, just a path and flags.
func scoutShellQuote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "'", "\\'") + "'"
}

func init() { rootCmd.AddCommand(newScoutCommand()) }
