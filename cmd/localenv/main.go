// localenv synchronizes encrypted local-development environment values.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/localenv/localenv/internal/cli"
)

var version = "dev"

func run(args []string, out io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(out, version)
		return 0
	}
	return cli.Run(args, out, out)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
