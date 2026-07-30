// GSAS CLI entry point.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "gsas is an in-process governance library; no standalone service is configured")
	os.Exit(1)
}
