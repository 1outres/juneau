package main

import (
	"context"
	"fmt"
	"os"

	"github.com/1outres/juneau/bgp-speaker/internal/speaker"
)

func main() {
	if err := speaker.NewApp().Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
