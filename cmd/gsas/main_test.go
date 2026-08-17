package main

// Regression test for the standalone supervised runtime contract.
//
// AIGOSD supervises cmd/gsas as a long-lived layer process. A prior
// hardening pass replaced the startup/run loop with an intentional
// nonzero exit. This test builds the binary, asserts the canonical
// startup line, verifies liveness, and then terminates the process.

import (
	"bufio"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const startupLine = "gsas layer running..."

func TestStandaloneRuntimeEmitsStartupLineAndStaysAlive(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "gsas-layer-smoke.exe")
	build := exec.Command("go", "build", "-o", exe, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the layer binary failed: %v\n%s", err, output)
	}

	cmd := exec.Command(exe)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("piping layer stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the layer process: %v", err)
	}
	finished := false
	defer func() {
		if !finished && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			lines <- scanner.Text()
			return
		}
		lines <- ""
	}()

	var startup string
	select {
	case startup = <-lines:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the canonical startup line")
	}
	if startup != startupLine {
		t.Fatalf("unexpected startup output %q, want %q", startup, startupLine)
	}

	// The supervised layer must remain alive until terminated externally.
	time.Sleep(2 * time.Second)
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		finished = true
		t.Fatalf("layer process exited instead of remaining alive: %v", err)
	case <-time.After(500 * time.Millisecond):
		// Still alive; terminate it cleanly to end the smoke window.
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("terminating the layer process: %v", err)
		}
		<-waited
		finished = true
	}
}
