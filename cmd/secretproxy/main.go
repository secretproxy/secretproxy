package main

import (
	"fmt"
	"os"

	"github.com/secretproxy/secretproxy/internal/app"
)

var version = "dev"

func main() {
	app.Version = version
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
