// Command tandemvault keeps selected 1Password items in step with SOPS/age vaults.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/frederikb96/tandemvault/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.New(version).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
