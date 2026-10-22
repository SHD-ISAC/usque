//go:build linux

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

type action struct {
	Kind      string   `json:"kind"`
	Family    int      `json:"family,omitempty"`
	Priority  int      `json:"priority,omitempty"`
	Selectors []string `json:"selectors,omitempty"`
}

type state struct {
	Owner      string   `json:"owner"`
	IfIndex    int      `json:"ifindex,omitempty"`
	Selected   Target   `json:"selected"`
	Ready      bool     `json:"ready"`
	CNEnabled  bool     `json:"cn_bypass,omitempty"`
	DNSServers []string `json:"dns_servers,omitempty"`
	Undo       []action `json:"undo"`
}

func (h *Host) save(st *state) error { return h.writeJSON("session.json", st) }

func (h *Host) addRule(ctx context.Context, st *state, family, pref int, selectors ...string) error {
	a := action{Kind: "rule", Family: family, Priority: pref, Selectors: selectors}
	st.Undo = append(st.Undo, a)
	if err := h.save(st); err != nil {
		return err
	}
	_, err := h.Exec(ctx, "ip", ruleArgs("add", a)...)
	return err
}

func ruleArgs(op string, a action) []string {
	args := []string{"-" + strconv.Itoa(a.Family), "rule", op, "priority", strconv.Itoa(a.Priority)}
	args = append(args, a.Selectors...)
	return append(args, "protocol", strconv.Itoa(protocol))
}

// Both families need bypasses before any scanner or reconnect can run while
// full-tunnel policies are active. The terminal rule prevents a missing physical
// default route from accidentally sending an outer packet into our own TUN.
func (h *Host) bypass(ctx context.Context, st *state) error {
	for _, family := range []int{4, 6} {
		prefix := team4.String()
		if family == 6 {
			prefix = team6.String()
		}
		if err := h.addRule(ctx, st, family, 18051, "to", prefix, "lookup", "main"); err != nil {
			return err
		}
		if err := h.addRule(ctx, st, family, 18052, "to", prefix, "unreachable"); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) deviceRoutes(ctx context.Context, st *state, cfg Config) error {
	for _, family := range []int{4, 6} {
		src := cfg.IPv4
		if family == 6 {
			src = cfg.IPv6
		}
		a := action{Kind: "route", Family: family}
		st.Undo = append(st.Undo, a)
		if err := h.save(st); err != nil {
			return err
		}
		_, err := h.Exec(ctx, "ip", "-"+strconv.Itoa(family), "route", "add", "table", strconv.Itoa(table), "default", "dev", Interface, "src", src, "proto", strconv.Itoa(protocol))
		if err != nil {
			return err
		}
		if err = h.addRule(ctx, st, family, 18050, "oif", Interface, "lookup", strconv.Itoa(table)); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) fullRoutes(ctx context.Context, st *state) error {
	for _, family := range []int{4, 6} {
		if err := h.addRule(ctx, st, family, 18053, "lookup", "main", "suppress_prefixlength", "0"); err != nil {
			return err
		}
		pref := 18054
		if st.CNEnabled {
			if err := h.addRule(ctx, st, family, 18054, "lookup", strconv.Itoa(cnTable)); err != nil {
				return err
			}
			pref = 18055
		}
		if err := h.addRule(ctx, st, family, pref, "lookup", strconv.Itoa(table)); err != nil {
			return err
		}
	}
	st.Undo = append(st.Undo, action{Kind: "dns"})
	if err := h.save(st); err != nil {
		return err
	}
	servers := st.DNSServers
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "1.0.0.1"}
	}
	commands := [][]string{append([]string{"dns", strconv.Itoa(st.IfIndex)}, servers...), {"domain", strconv.Itoa(st.IfIndex), "~."}, {"default-route", strconv.Itoa(st.IfIndex), "yes"}, {"llmnr", strconv.Itoa(st.IfIndex), "no"}, {"mdns", strconv.Itoa(st.IfIndex), "no"}}
	if len(st.DNSServers) > 0 {
		commands = append(commands, []string{"dnsovertls", strconv.Itoa(st.IfIndex), "no"})
	}
	commands = append(commands, []string{"flush-caches"})
	for _, args := range commands {
		if _, err := h.Exec(ctx, "resolvectl", args...); err != nil {
			return err
		}
	}
	return nil
}

func validAction(a action) bool {
	if a.Kind == "dns" {
		return a.Family == 0 && a.Priority == 0 && len(a.Selectors) == 0
	}
	if a.Family != 4 && a.Family != 6 {
		return false
	}
	if a.Kind == "route" {
		return a.Priority == 0 && len(a.Selectors) == 0
	}
	if a.Kind == "cnroutes" {
		return a.Priority == 0 && len(a.Selectors) == 0
	}
	if a.Kind != "rule" {
		return false
	}
	prefix := team4.String()
	if a.Family == 6 {
		prefix = team6.String()
	}
	allowed := map[int][]string{18050: {"oif", Interface, "lookup", strconv.Itoa(table)}, 18051: {"to", prefix, "lookup", "main"}, 18052: {"to", prefix, "unreachable"}, 18053: {"lookup", "main", "suppress_prefixlength", "0"}, 18054: {"lookup", strconv.Itoa(table)}}
	if a.Priority == 18054 && slices.Equal(a.Selectors, []string{"lookup", strconv.Itoa(cnTable)}) {
		return true
	}
	if a.Priority == 18055 && slices.Equal(a.Selectors, []string{"lookup", strconv.Itoa(table)}) {
		return true
	}
	selectors, ok := allowed[a.Priority]
	return ok && slices.Equal(a.Selectors, selectors)
}

func (h *Host) rollback(ctx context.Context, st *state, keep int) error {
	var failed []action
	var failures []error
	for i := len(st.Undo) - 1; i >= keep; i-- {
		a := st.Undo[i]
		err := func() error {
			if !validAction(a) {
				return fmt.Errorf("unrecognized cleanup action (state retained)")
			}
			iface, err := net.InterfaceByName(Interface)
			same := err == nil && iface.Index == st.IfIndex
			switch a.Kind {
			case "cnroutes":
				// Only our dedicated CN table and protocol marker are removed.
				routes, e := h.ip(ctx, a.Family, "route", "show", "table", strconv.Itoa(cnTable))
				if e != nil {
					return e
				}
				for _, r := range routes {
					p, _ := number(r["protocol"])
					if p == protocol {
						_, err = h.Exec(ctx, "ip", "-"+strconv.Itoa(a.Family), "route", "flush", "table", strconv.Itoa(cnTable), "proto", strconv.Itoa(protocol))
						return err
					}
				}
				return nil
			case "dns":
				if !same {
					return nil
				}
				_, err = h.Exec(ctx, "resolvectl", "revert", strconv.Itoa(st.IfIndex))
				return err
			case "route":
				if !same {
					return nil
				}
				routes, err := h.ip(ctx, a.Family, "route", "show", "table", strconv.Itoa(table))
				if err != nil {
					return err
				}
				for _, r := range routes {
					p, _ := number(r["protocol"])
					if r["dst"] == "default" && r["dev"] == Interface && p == protocol {
						_, err = h.Exec(ctx, "ip", "-"+strconv.Itoa(a.Family), "route", "del", "table", strconv.Itoa(table), "default", "dev", Interface, "proto", strconv.Itoa(protocol))
						return err
					}
				}
				return nil
			case "rule":
				rules, err := h.ip(ctx, a.Family, "rule", "show")
				if err != nil {
					return err
				}
				for _, r := range rules {
					pref, _ := number(r["priority"])
					p, _ := number(r["protocol"])
					if pref == a.Priority && p == protocol {
						_, err = h.Exec(ctx, "ip", ruleArgs("del", a)...)
						return err
					}
				}
				return nil
			}
			return nil
		}()
		if err != nil {
			failed = append(failed, a)
			failures = append(failures, err)
		}
	}
	slices.Reverse(failed)
	st.Undo = append(st.Undo[:keep:keep], failed...)
	st.Ready = false
	if err := h.save(st); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// Cleanup is also called by systemd ExecStopPost after an unexpected process
// exit. It only replays recognized, individually recorded Usque operations.
func (h *Host) Cleanup(ctx context.Context) error {
	var st state
	if err := h.readJSON("session.json", &st); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if st.Owner != "usque-native-v1" {
		return fmt.Errorf("runtime state belongs to another application")
	}
	if err := h.rollback(ctx, &st, 0); err != nil {
		return err
	}
	return os.Remove(filepath.Join(h.Dir, "session.json"))
}
