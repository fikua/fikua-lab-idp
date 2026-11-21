// Command healthcheck is the image's HEALTHCHECK (fikua-docs conv-deployment.md,
// DEP-10). An image may hold several binaries and the compose file picks one
// as the entrypoint, so this asks the running one: it reads the program of
// PID 1 and runs "<program> healthcheck", which probes that binary's own port.
package main

import (
	"bytes"
	"os"
	"syscall"
)

func main() {
	cmdline, err := os.ReadFile("/proc/1/cmdline")
	if err != nil || len(cmdline) == 0 {
		os.Exit(1)
	}
	prog := string(bytes.SplitN(cmdline, []byte{0}, 2)[0])
	if prog == "" || prog == os.Args[0] {
		os.Exit(1)
	}
	_ = syscall.Exec(prog, []string{prog, "healthcheck"}, os.Environ())
	os.Exit(1)
}
