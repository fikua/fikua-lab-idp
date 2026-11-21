// Command healthcheck is the image's HEALTHCHECK (fikua-docs conv-deployment.md,
// DEP-10): it runs "<binary> healthcheck" for whichever binary is PID 1.
package main

import (
	"os"

	"github.com/fikua/fikua-lab-idp/internal/health"
)

func main() { os.Exit(health.RunForPID1()) }
