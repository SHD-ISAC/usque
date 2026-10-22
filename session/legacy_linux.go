//go:build linux

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const legacyHash = "741895707a6d0e2ee400bd0801416d192f50374df6a0c16279f4084b16435810"

func inspectLegacy(dir string) ([]string, error) {
	return inspectLegacyHash(dir, legacyHash)
}

func inspectLegacyHash(dir, expected string) ([]string, error) {
	helper := filepath.Join(dir, "usque-session")
	var files []string
	if info, err := os.Lstat(helper); err == nil {
		if !info.Mode().IsRegular() || info.Size() > 128<<10 {
			return nil, fmt.Errorf("legacy helper is not a small regular file; left unchanged")
		}
		data, err := os.ReadFile(helper)
		if err != nil {
			return nil, err
		}
		if digest(data) != expected {
			return nil, fmt.Errorf("legacy helper differs from the verified 1.0.1 script; left unchanged")
		}
		files = append(files, helper)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, name := range []string{"usque-up", "usque-down"} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil, fmt.Errorf("%s is not the legacy symlink; left unchanged", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		if target != "usque-session" && target != helper {
			return nil, fmt.Errorf("%s points somewhere else; left unchanged", path)
		}
		files = append(files, path)
	}
	return files, nil
}

// Only the known installed script and its two symlinks are removed. The native
// binary, current runtime, original registration and Downloads are untouched.
func CleanupLegacy(ctx context.Context, plan bool) ([]string, error) {
	const dir = "/usr/local/bin"
	files, err := inspectLegacy(dir)
	if err != nil || plan {
		return files, err
	}
	helper := filepath.Join(dir, "usque-session")
	_, helperErr := os.Lstat(helper)
	h := NewHost()
	_, stateErr := os.Lstat("/run/usque-session/state.json")
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	unit, queryErr := h.Exec(ctx, "systemctl", "show", "usque-manual.service", "--property=LoadState,Transient")
	if queryErr != nil && !strings.Contains(string(unit), "LoadState=not-found") {
		return nil, queryErr
	}
	if !strings.Contains(string(unit), "LoadState=not-found") && !strings.Contains(string(unit), "Transient=yes") {
		return nil, fmt.Errorf("legacy unit is not transient; left unchanged")
	}
	oldActive := h.active(ctx, "usque-manual.service")
	if oldActive || stateErr == nil {
		if h.active(ctx, Unit) {
			return nil, fmt.Errorf("stop the native session with usque down before recovering the legacy session state")
		}
		if helperErr != nil {
			return nil, fmt.Errorf("legacy session needs cleanup but the verified old helper is missing")
		}
		if err = TrustedExecutable(helper); err != nil {
			return nil, err
		}
		if _, err = longCommand(ctx, 110*time.Second, "/usr/local/bin/usque-session", "down"); err != nil {
			return nil, fmt.Errorf("legacy stop/cleanup failed; no files removed: %w", err)
		}
	}
	// Recheck immediately before unlinking. Unexpected files are never forced.
	current, err := inspectLegacy(dir)
	if err != nil {
		return nil, err
	}
	for _, path := range current {
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	_ = os.Remove("/run/usque-session") // only succeeds if the old directory is empty
	return current, nil
}
