//go:build linux

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestScoutSignalHelper(t *testing.T) {
	if os.Getenv("USQUE_SCOUT_SIGNAL_TEST") != "1" {
		return
	}
	ctx, stop := scoutSignalContext(context.Background())
	defer stop()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("cancelled")
}

func TestScoutHandlesInterruptAndTermination(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScoutSignalHelper$")
			child.Env = append(os.Environ(), "USQUE_SCOUT_SIGNAL_TEST=1")
			stdout, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = child.Process.Kill() })
			scanner := bufio.NewScanner(stdout)
			if !scanner.Scan() || scanner.Text() != "ready" {
				_ = child.Wait()
				t.Fatal("signal helper did not start")
			}
			if err := child.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if !scanner.Scan() || scanner.Text() != "cancelled" {
				_ = child.Wait()
				t.Fatalf("%s did not cancel the scan", sig)
			}
			if err := child.Wait(); err != nil {
				t.Fatalf("%s killed the process instead of cancelling: %v", sig, err)
			}
		})
	}
}
