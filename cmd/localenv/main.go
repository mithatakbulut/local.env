// localenv synchronizes encrypted local-development environment values.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

var version = "dev"

func run(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("localenv", flag.ContinueOnError)
	flags.SetOutput(out)
	showVersion := flags.Bool("version", false, "print version")
	flags.Usage = func() {
		fmt.Fprintln(out, "Usage: localenv [--version]")
		fmt.Fprintln(out, "\nCLI commands will be added in subsequent v1 phases.")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(out, version)
		return 0
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	flags.Usage()
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
