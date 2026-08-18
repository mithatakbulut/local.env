// localenv synchronizes encrypted local-development environment values.
package main

import (
	"io"
	"os"

	"github.com/localenv/localenv/internal/cli"
)

var version = "dev"

func run(args []string, out, errOut io.Writer) int {
	cli.Version = version
	return cli.Run(args, out, errOut)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
