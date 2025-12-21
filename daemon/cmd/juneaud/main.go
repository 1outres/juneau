package main

import (
	"context"
	"fmt"
	"os"

	"github.com/1outres/juneau/daemon/internal/daemon"
)

func main() {
	if err := daemon.NewApp().Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
