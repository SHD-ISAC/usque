//go:build linux

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	Executable, ConfigPath, Family                        string
	RegistrationDigest                                    string
	OwnerUID, LauncherPID                                 int
	Ports                                                 []int
	BypassCN, GeoIPFile, GeoSiteFile                      string
	CNDNS                                                 []string
	ProbeTimeout, FamilyBudget, HealthInterval, IPv6Retry time.Duration
}

func DefaultOptions() Options {
	return Options{Family: "prefer6", BypassCN: "off", CNDNS: []string{"223.5.5.5:53", "[2400:3200::1]:53"}, Ports: []int{500, 4500, 443, 1701, 4443, 8443, 8095}, ProbeTimeout: 6 * time.Second, FamilyBudget: 24 * time.Second, HealthInterval: 30 * time.Second, IPv6Retry: 5 * time.Minute}
}

func (o Options) Validate() error {
	_, domain, err := cnMode(o.BypassCN)
	if err != nil {
		return err
	}
	if domain {
		if _, err := parseDNSServers(o.CNDNS); err != nil {
			return err
		}
	}
	if o.Family != "prefer6" && o.Family != "4" && o.Family != "6" {
		return fmt.Errorf("family must be prefer6, 4 or 6")
	}
	if o.ProbeTimeout < time.Second || o.ProbeTimeout > 30*time.Second || o.FamilyBudget < o.ProbeTimeout || o.FamilyBudget > 2*time.Minute {
		return fmt.Errorf("probe timeout must be 1s..30s; family budget must be timeout..2m")
	}
	if o.HealthInterval < 10*time.Second || o.HealthInterval > 10*time.Minute || o.IPv6Retry < 30*time.Second || o.IPv6Retry > time.Hour {
		return fmt.Errorf("health interval must be 10s..10m; IPv6 retry must be 30s..1h")
	}
	_, err = BuildTargets("", "", o.Ports)
	return err
}

type cache struct {
	Target                Target `json:"target"`
	Network, Registration string
	At                    time.Time
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (h *Host) cacheTarget(network, registration string, targets []Target) Target {
	var c cache
	if h.readJSON("last-endpoint.json", &c) != nil || c.Network != network || c.Registration != registration || time.Since(c.At) < 0 || time.Since(c.At) > 24*time.Hour || !c.Target.Valid() || !slices.Contains(targets, c.Target) {
		return Target{}
	}
	return c.Target
}

func (h *Host) UnitState(ctx context.Context) (string, error) {
	data, err := h.Exec(ctx, "systemctl", "show", Unit, "--property=LoadState,Transient,ActiveState,SubState,StatusText")
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = v
		}
	}
	if err != nil && values["LoadState"] != "not-found" {
		return "", fmt.Errorf("cannot query system systemd manager: %w", err)
	}
	if values["LoadState"] != "" && values["LoadState"] != "not-found" && values["Transient"] != "yes" {
		return "", fmt.Errorf("%s belongs to a non-transient unit", Unit)
	}
	return string(data), nil
}

func StartArgs(o Options) []string {
	args := []string{"--unit=" + Unit, "--collect", "--expand-environment=no", "--description=Manual adaptive Usque TUN (no autostart)", "--property=Type=notify", "--property=NotifyAccess=main", "--property=Restart=no", "--property=TimeoutStartSec=300s", "--property=TimeoutStopSec=45s", "--property=KillMode=control-group", "--property=RuntimeDirectory=usque-native", "--property=RuntimeDirectoryMode=0700", "--property=RuntimeDirectoryPreserve=yes", "--property=UMask=0077", "--property=NoNewPrivileges=yes", "--property=ExecStopPost=" + o.Executable + " _session-cleanup", o.Executable, "_session-run", "--config", o.ConfigPath, "--family", o.Family, "--ports", joinPorts(o.Ports), "--probe-timeout", o.ProbeTimeout.String(), "--family-budget", o.FamilyBudget.String(), "--health-interval", o.HealthInterval.String(), "--ipv6-retry", o.IPv6Retry.String(), "--owner-uid", strconv.Itoa(o.OwnerUID), "--launcher-pid", strconv.Itoa(os.Getpid())}
	args = append(args, "--bypass-cn="+o.BypassCN, "--geoip-file", o.GeoIPFile, "--geosite-file", o.GeoSiteFile, "--cn-dns", strings.Join(o.CNDNS, ","))
	return args
}

func joinPorts(ports []int) string {
	var s []string
	for _, p := range ports {
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ",")
}

func longCommand(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	path, err := tool(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = cleanEnv()
	cmd.WaitDelay = 2 * time.Second
	data, err := cmd.CombinedOutput()
	if err != nil {
		return data, fmt.Errorf("%s: %w", name, err)
	}
	return data, nil
}

func (h *Host) Start(ctx context.Context, o Options) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := TrustedExecutable(o.Executable); err != nil {
		return err
	}
	unit, err := h.UnitState(ctx)
	if err != nil {
		return err
	}
	if strings.Contains(unit, "ActiveState=active\n") || strings.Contains(unit, "ActiveState=activating\n") || strings.Contains(unit, "ActiveState=deactivating\n") {
		return fmt.Errorf("session already active or changing; use usque down first")
	}
	if _, err := os.Lstat(filepath.Join(h.Dir, "session.json")); err == nil {
		return fmt.Errorf("unfinished cleanup state exists; run usque down first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cfg, _, err := ReadConfig(o.ConfigPath, o.OwnerUID)
	if err != nil {
		return err
	}
	if err = h.Preflight(ctx, cfg); err != nil {
		return err
	}
	if data, err := LoadCNData(o.BypassCN, o.GeoIPFile, o.GeoSiteFile); err != nil {
		return err
	} else if data != nil {
		if err = h.checkCNTable(ctx); err != nil {
			return err
		}
	}
	data, err := longCommand(ctx, 350*time.Second, "systemd-run", StartArgs(o)...)
	if err != nil {
		_ = h.Stop(context.Background())
		return fmt.Errorf("startup failed; cleanup requested: %w\n%s\nInspect: journalctl -u %s -n 60 --no-pager", err, string(data), Unit)
	}
	fmt.Printf("Usque dual-stack TUN ready; IPv6 preference=%s. Stop with: usque down\n", o.Family)
	return nil
}

func (h *Host) Stop(ctx context.Context) error {
	unit, err := h.UnitState(ctx)
	if err != nil {
		return err
	}
	if !strings.Contains(unit, "LoadState=not-found") && strings.Contains(unit, "LoadState=") {
		if _, err := longCommand(ctx, 90*time.Second, "systemctl", "stop", Unit); err != nil {
			return err
		}
		_, _ = h.Exec(ctx, "systemctl", "reset-failed", Unit)
	}
	return h.Cleanup(ctx)
}

func notify(message string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return fmt.Errorf("session runner must be started by usque up through systemd")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(message))
	return err
}

type child struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
}

func startChild(o Options, target Target) (*child, error) {
	args := []string{"-c", o.ConfigPath, "nativetun", "-n", Interface, "-s", "zt-masque.cloudflareclient.com", "--endpoint", target.IP.String(), "-P", strconv.Itoa(int(target.Port)), "--always-reconnect"}
	if target.IP.Is6() {
		args = append(args, "-6")
	}
	cmd := exec.Command(o.Executable, args...)
	cmd.Env = cleanEnv()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{command: cmd, done: make(chan struct{})}
	go func() { c.err = cmd.Wait(); close(c.done) }()
	return c, nil
}

func (c *child) stop() {
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		_ = c.command.Process.Kill()
		<-c.done
	}
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (h *Host) validateRoutes(ctx context.Context, selected Target) error {
	for _, item := range []struct {
		family int
		ip     string
	}{{4, "1.0.0.1"}, {6, "2606:4700:4700::1111"}} {
		r, err := h.ip(ctx, item.family, "route", "get", item.ip)
		if err != nil {
			return err
		}
		if len(r) == 0 || r[0]["dev"] != Interface {
			return fmt.Errorf("inner IPv%d default traffic is not using the TUN", item.family)
		}
	}
	if _, err := h.Route(ctx, selected.IP); err != nil {
		return fmt.Errorf("selected endpoint bypass failed: %w", err)
	}
	return nil
}

// Run supervises a native TUN child from the same installed binary. This keeps
// legacy nativetun users unchanged and lets a stuck transport be terminated as a
// process before a new endpoint is tried. No Python helper is required.
func (h *Host) Run(ctx context.Context, o Options, probe Probe) (result error) {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := TrustedExecutable(o.Executable); err != nil {
		return err
	}
	cfg, original, err := ReadConfig(o.ConfigPath, o.OwnerUID)
	if err != nil {
		return err
	}
	if o.RegistrationDigest != "" && digest(original) != o.RegistrationDigest {
		return fmt.Errorf("configuration changed while preparing its pinned probe engine")
	}
	if err = h.Preflight(ctx, cfg, o.LauncherPID); err != nil {
		return err
	}
	cnData, err := LoadCNData(o.BypassCN, o.GeoIPFile, o.GeoSiteFile)
	if err != nil {
		return err
	}
	var cnServers []netip.AddrPort
	if cnData != nil {
		if err = h.checkCNTable(ctx); err != nil {
			return err
		}
		_, domain, _ := cnMode(o.BypassCN)
		if domain {
			cnServers, err = parseDNSServers(o.CNDNS)
			if err != nil {
				return err
			}
		}
		log.Printf("CN bypass mode=%s: %d IP prefixes, %d domain rules; using local Xray data read-only", o.BypassCN, len(cnData.Prefixes), cnData.DomainCount())
	}
	if err = h.privateDir(); err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(h.Dir, "session.json")); err == nil {
		return fmt.Errorf("unfinished session state exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	st := &state{Owner: "usque-native-v1"}
	if err = h.save(st); err != nil {
		return err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		result = errors.Join(result, h.Cleanup(cleanCtx))
	}()
	if err = h.bypass(ctx, st); err != nil {
		return err
	}
	base := len(st.Undo)
	targets, err := BuildTargets(cfg.Endpoint4, cfg.Endpoint6, o.Ports)
	if err != nil {
		return err
	}
	network := h.NetworkKey(ctx, targets)
	registration := digest(original)
	selector := &Selector{Family: o.Family, Timeout: o.ProbeTimeout, Budget: o.FamilyBudget, Workers: 2, Targets: targets, Probe: probe, Reachable: func(ctx context.Context, ip netip.Addr) bool { _, err := h.Route(ctx, ip); return err == nil }, Log: log.Printf, Bad: map[Target]time.Time{}}
	selector.Last = h.cacheTarget(network, registration, targets)
	startup := time.Now().Add(210 * time.Second)
	announced := false
	var next Target
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !announced && time.Now().After(startup) {
			return fmt.Errorf("startup deadline exceeded: %w", ErrNoEndpoint)
		}
		if err = h.NoOtherVPN(ctx); err != nil {
			return err
		}
		if _, data, e := ReadConfig(o.ConfigPath, o.OwnerUID); e != nil {
			return e
		} else if digest(data) != registration {
			return fmt.Errorf("original configuration changed; stopping without overwriting it")
		}
		selected := next
		next = Target{}
		if !selected.Valid() {
			selectCtx, cancel := context.WithCancel(ctx)
			if !announced {
				cancel()
				selectCtx, cancel = context.WithDeadline(ctx, startup)
			}
			selected, err = selector.Select(selectCtx, false)
			cancel()
			if err != nil {
				if errors.Is(err, ErrProbeStalled) {
					return err
				}
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("No verified endpoint yet; retrying after 10s: %v", err)
				if wait(ctx, 10*time.Second) != nil {
					return nil
				}
				continue
			}
		}
		st.Selected = selected
		st.CNEnabled = false
		st.DNSServers = nil
		log.Printf("Selected original-key Team QUIC endpoint %s", selected)
		c, err := startChild(o, selected)
		if err != nil {
			return err
		}
		cycleErr := func() error {
			var cn *cnRouter
			var dns *splitDNS
			defer func() {
				if dns != nil {
					dns.Close()
				}
				if cn != nil {
					cn.Close()
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				select {
				case <-c.done:
					return fmt.Errorf("native TUN process exited: %v", c.err)
				default:
				}
				link, e := net.InterfaceByName(Interface)
				if e == nil && link.Flags&net.FlagUp != 0 {
					st.IfIndex = link.Index
					break
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("TUN interface did not become ready")
				}
				if wait(ctx, 100*time.Millisecond) != nil {
					return ctx.Err()
				}
			}
			if err := h.deviceRoutes(ctx, st, cfg); err != nil {
				return err
			}
			checkCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			health, err := Check(checkCtx, Interface)
			cancel()
			if err != nil {
				return err
			}
			for _, v := range health {
				log.Printf("Native TUN IPv%d UDP DNS + verified HTTPS: warp=%s colo=%s", v.Family, v.Warp, v.Colo)
			}
			cycleNetwork := h.NetworkKey(ctx, targets)
			if cnData != nil {
				cn, err = h.installCN(ctx, st, cnData, cnServers)
				if err != nil {
					return err
				}
				_, domains, _ := cnMode(o.BypassCN)
				if domains {
					dns, err = startSplitDNS(ctx, netip.MustParseAddr(cfg.IPv4), cn, cnData, cnServers)
					if err != nil {
						return err
					}
					st.DNSServers = []string{dns.Server()}
				}
			}
			if err = h.fullRoutes(ctx, st); err != nil {
				return err
			}
			if err = h.validateRoutes(ctx, selected); err != nil {
				return err
			}
			if h.NetworkKey(ctx, targets) != cycleNetwork {
				return errNetworkChanged
			}
			if _, err = h.Exec(ctx, "resolvectl", "--interface", Interface, "--type=A", "query", traceHost); err != nil {
				return err
			}
			st.Ready = true
			if err = h.save(st); err != nil {
				return err
			}
			selector.Last = selected
			network = h.NetworkKey(ctx, targets)
			if e := h.writeJSON("last-endpoint.json", cache{selected, network, registration, time.Now().UTC()}); e != nil {
				log.Printf("Endpoint cache not saved: %v", e)
			}
			if err = notify("READY=1\nSTATUS=Dual-stack TUN ready; QUIC " + selected.String() + "; family=" + o.Family); err != nil {
				return err
			}
			announced = true
			checkTick := time.NewTicker(o.HealthInterval)
			defer checkTick.Stop()
			networkTick := time.NewTicker(10 * time.Second)
			defer networkTick.Stop()
			v6Tick := time.NewTicker(o.IPv6Retry)
			defer v6Tick.Stop()
			failures := 0
			var dnsErrors <-chan error
			if dns != nil {
				dnsErrors = dns.err
			}
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-c.done:
					return fmt.Errorf("native TUN process exited: %v", c.err)
				case e := <-dnsErrors:
					return e
				case <-networkTick.C:
					if err = h.NoOtherVPN(ctx); err != nil {
						return err
					}
					if current := h.NetworkKey(ctx, targets); current != network {
						network = current
						selector.Bad = map[Target]time.Time{}
						return errNetworkChanged
					}
				case <-checkTick.C:
					checkCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
					_, e := Check(checkCtx, Interface)
					cancel()
					if e == nil {
						failures = 0
					} else {
						failures++
						log.Printf("Tunnel health check failed (%d/3): %v", failures, e)
					}
					if failures >= 3 {
						return fmt.Errorf("three consecutive end-to-end health checks failed")
					}
				case <-v6Tick.C:
					if o.Family == "prefer6" && selected.IP.Is4() {
						v6, e := selector.Select(ctx, true)
						if errors.Is(e, ErrProbeStalled) {
							return e
						}
						if e == nil {
							next = v6
							return errPreferIPv6
						}
					}
				}
			}
		}()
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanErr := h.rollback(cleanCtx, st, base)
		cancel()
		c.stop()
		st.IfIndex = 0
		if cleanErr != nil {
			return cleanErr
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(cycleErr, ErrProbeStalled) {
			return cycleErr
		}
		if err = h.NoOtherVPN(ctx); err != nil {
			return err
		}
		if errors.Is(cycleErr, errNetworkChanged) {
			log.Printf("Physical network changed; selecting an endpoint again")
			selector.Last = Target{}
		} else if errors.Is(cycleErr, errPreferIPv6) {
			log.Printf("Verified IPv6 is available again; switching to %s", next)
		} else {
			selector.Bad[selected] = time.Now().Add(2 * time.Minute)
			log.Printf("Endpoint %s failed; selecting another combination: %v", selected, cycleErr)
		}
		if wait(ctx, 3*time.Second) != nil {
			return nil
		}
	}
}

var errNetworkChanged = errors.New("physical network changed")
var errPreferIPv6 = errors.New("verified IPv6 is available")
