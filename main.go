package main

import (
	"os"

	"github.com/rebaze/rio/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
