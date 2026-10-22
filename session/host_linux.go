//go:build linux

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Unit = "usque-native.service"
const Runtime = "/run/usque-native"
const table = 51871
const protocol = 199
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type Executor func(context.Context, string, ...string) ([]byte, error)
type Host struct {
	Exec     Executor
	Dir      string
	stateUID uint32 // production defaults to root; tests use a private fixture owner
}

func NewHost() *Host { return &Host{Exec: execute, Dir: Runtime} }

func tool(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(safePath) {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("required existing command not found: %s", name)
}

func cleanEnv() []string {
	return []string{"PATH=" + safePath, "LC_ALL=C", "LANG=C", "PAGER=cat", "SYSTEMD_PAGER=cat"}
}

func execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := tool(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = cleanEnv()
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(stderr.String())
		if len(text) > 800 {
			text = text[:800]
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, text)
	}
	if stdout.Len() > 2<<20 {
		return nil, fmt.Errorf("%s output exceeds limit", name)
	}
	return stdout.Bytes(), nil
}

func (h *Host) ip(ctx context.Context, family int, args ...string) ([]map[string]any, error) {
	data, err := h.Exec(ctx, "ip", append([]string{"-j", "-N", "-" + strconv.Itoa(family)}, args...)...)
	if err != nil {
		if strings.Contains(err.Error(), "FIB table does not exist") {
			return nil, nil
		}
		return nil, err
	}
	var out []map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	err = d.Decode(&out)
	return out, err
}

func number(value any) (int, error) {
	switch v := value.(type) {
	case string:
		if v == "local" {
			return 255, nil
		}
		if v == "main" {
			return 254, nil
		}
		if v == "default" {
			return 253, nil
		}
		if v == "usque" {
			return protocol, nil
		}
		n, err := strconv.ParseUint(v, 10, 32)
		return int(n), err
	case json.Number:
		n, err := strconv.ParseUint(string(v), 10, 32)
		return int(n), err
	default:
		return 0, fmt.Errorf("not an unsigned integer")
	}
}

func validateRules(rules []map[string]any) error {
	expected := map[int]int{0: 255, 32766: 254, 32767: 253}
	seen := map[int]bool{}
	for _, r := range rules {
		pref, e1 := number(r["priority"])
		lookup, e2 := number(r["table"])
		if e1 != nil || e2 != nil || expected[pref] != lookup || seen[pref] || lookup == 0 {
			return fmt.Errorf("custom policy rule: %v (no existing rules changed)", r)
		}
		for k, v := range r {
			switch k {
			case "priority", "table", "protocol":
			case "src", "dst":
				if v != "all" && v != "0.0.0.0/0" && v != "::/0" {
					return fmt.Errorf("custom source/destination rule: %v", r)
				}
			default:
				return fmt.Errorf("unsupported policy selector %s: %v", k, r)
			}
		}
		seen[pref] = true
	}
	if !seen[0] || !seen[32766] {
		return fmt.Errorf("standard local/main rules are missing")
	}
	return nil
}

func uid(info os.FileInfo) uint32 { return info.Sys().(*syscall.Stat_t).Uid }

func TrustedExecutable(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\n\r%$\t \"'") {
		return fmt.Errorf("installed executable path is not suitable for systemd")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || uid(info) != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("executable and its ancestors must be root-owned and not writable by others: %s", p)
		}
		if p == path && (!info.Mode().IsRegular() || info.Mode()&0111 == 0) {
			return fmt.Errorf("expected installed executable")
		}
		if p == "/" {
			break
		}
	}
	return nil
}

type Config struct {
	Endpoint4  string `json:"endpoint_v4"`
	Endpoint6  string `json:"endpoint_v6"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	PrivateKey string `json:"private_key"`
	Pin        string `json:"endpoint_pub_key"`
}

func ReadConfig(path string, owner int) (Config, []byte, error) {
	var cfg Config
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\n\r%$") {
		return cfg, nil, fmt.Errorf("config needs an absolute path without newline, %% or $")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return cfg, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return cfg, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || (uid(info) != 0 && uid(info) != uint32(owner)) {
		return cfg, nil, fmt.Errorf("config must be a private regular file (0600 or stricter), owned by you or root")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return cfg, nil, err
	}
	if len(data) >= 1<<20 {
		return cfg, nil, fmt.Errorf("config too large")
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, nil, fmt.Errorf("invalid config JSON")
	}
	v4, e4 := netip.ParseAddr(cfg.IPv4)
	v6, e6 := netip.ParseAddr(cfg.IPv6)
	if e4 != nil || e6 != nil || !v4.Is4() || !v6.Is6() || v6.Is4In6() || !v4.IsGlobalUnicast() || !v6.IsGlobalUnicast() || cfg.PrivateKey == "" || cfg.Pin == "" {
		return cfg, nil, fmt.Errorf("original config needs dual-stack tunnel addresses and existing device key/public-key pin")
	}
	if _, err := BuildTargets(cfg.Endpoint4, cfg.Endpoint6, []int{500}); err != nil {
		return cfg, nil, err
	}
	return cfg, data, nil
}

func (h *Host) active(ctx context.Context, name string) bool {
	_, err := h.Exec(ctx, "systemctl", "is-active", "--quiet", name)
	return err == nil
}

func (h *Host) Preflight(ctx context.Context, cfg Config, excludePIDs ...int) error {
	for _, name := range []string{"ip", "systemctl", "systemd-run", "resolvectl"} {
		if _, err := tool(name); err != nil {
			return err
		}
	}
	if !h.active(ctx, "systemd-resolved") {
		return fmt.Errorf("existing systemd-resolved must be active")
	}
	if err := h.NoOtherVPN(ctx); err != nil {
		return err
	}
	entries, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, p := range entries {
		pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(p)))
		skip := pid == os.Getpid()
		for _, v := range excludePIDs {
			if pid == v {
				skip = true
			}
		}
		if data, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(data)) == "usque" && !skip {
			return fmt.Errorf("another Usque process is running (PID %d)", pid)
		}
	}
	resolv, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	var servers []string
	for _, line := range strings.Split(string(resolv), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	if len(servers) != 1 || servers[0] != "127.0.0.53" {
		return fmt.Errorf("resolv.conf must already use only the existing resolved stub 127.0.0.53")
	}
	domains, err := h.Exec(ctx, "resolvectl", "domain")
	if err != nil {
		return err
	}
	for _, f := range strings.Fields(string(domains)) {
		if f == "~." {
			return fmt.Errorf("another DNS setting already owns ~.")
		}
	}
	links, err := h.ip(ctx, 4, "link", "show")
	if err != nil {
		return err
	}
	for _, link := range links {
		if link["ifname"] == Interface {
			return fmt.Errorf("%s already exists", Interface)
		}
	}
	for _, family := range []int{4, 6} {
		rules, err := h.ip(ctx, family, "rule", "show")
		if err != nil {
			return err
		}
		if err = validateRules(rules); err != nil {
			return fmt.Errorf("IPv%d: %w", family, err)
		}
		routes, err := h.ip(ctx, family, "route", "show", "table", strconv.Itoa(table))
		if err != nil {
			return err
		}
		if len(routes) > 0 {
			return fmt.Errorf("routing table %d is already in use", table)
		}
	}
	return nil
}

func (h *Host) NoOtherVPN(ctx context.Context) error {
	for _, name := range []string{"xray", "warp-svc", "usque-manual.service"} {
		if h.active(ctx, name) {
			return fmt.Errorf("%s is active; stop it before using the integrated tunnel", name)
		}
	}
	return nil
}

// A hash of stable physical route fields detects uplink/address changes without
// treating RA lifetimes and route-cache ages as network changes.
func (h *Host) Route(ctx context.Context, ip netip.Addr) (string, error) {
	family := 4
	if ip.Is6() {
		family = 6
	}
	routes, err := h.ip(ctx, family, "route", "get", ip.String())
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("no route")
	}
	r := routes[0]
	dev, _ := r["dev"].(string)
	if dev == "" || dev == Interface || dev == "lo" || dev == "xray0" {
		return "", fmt.Errorf("no physical route")
	}
	if typ, ok := r["type"].(string); ok && typ != "unicast" {
		return "", fmt.Errorf("non-unicast route")
	}
	src, _ := r["prefsrc"].(string)
	if src == "" {
		src, _ = r["src"].(string)
	}
	addr, err := netip.ParseAddr(src)
	if err != nil || addr.Is4() != ip.Is4() || (ip.Is6() && !publicIP(addr)) {
		return "", fmt.Errorf("no usable physical source address")
	}
	return fmt.Sprint(dev, "|", r["gateway"], "|", src), nil
}

func (h *Host) NetworkKey(ctx context.Context, targets []Target) string {
	seen := map[bool]bool{}
	var parts []string
	for _, t := range targets {
		v6 := t.IP.Is6()
		if seen[v6] {
			continue
		}
		seen[v6] = true
		r, err := h.Route(ctx, t.IP)
		if err != nil {
			r = "unavailable"
		}
		parts = append(parts, strconv.FormatBool(v6)+":"+r)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";")))
	return hex.EncodeToString(sum[:])
}

func (h *Host) privateDir() error {
	info, err := os.Lstat(h.Dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || uid(info) != h.stateUID || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("unsafe runtime directory")
	}
	return nil
}

func (h *Host) writeJSON(name string, v any) error {
	if err := h.privateDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(h.Dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(h.Dir, name))
}

func (h *Host) readJSON(name string, v any) error {
	if err := h.privateDir(); err != nil {
		return err
	}
	path := filepath.Join(h.Dir, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || uid(info) != h.stateUID || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("unsafe runtime state file")
	}
	return json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(v)
}
