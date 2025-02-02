// currently there is no way to validate blocks with differences in
// difficulty, idk if it gets added but adding as comment for now

package main

import (
	"os"
	"github.com/Scrimzay/tensorblockchaintut/cli"
)

func main() {
	defer os.Exit(0)
	cmd := cli.CommandLine{}
	cmd.Run()
}