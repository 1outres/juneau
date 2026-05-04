package main

import (
	"context"
	"fmt"
	"os"

	"github.com/1outres/juneau/daemon/internal/daemon"
	"github.com/urfave/cli/v3"
)

func main() {
	root := &cli.Command{
		Name: "juneaud",
		Commands: []*cli.Command{
			daemon.NewApp(),
			daemon.NewRelayApp(),
		},
		// Keep the legacy "no subcommand" invocation working — old
		// daemonset specs call /juneaud directly with flags. Forward
		// to the daemon command so behaviour is unchanged.
		Action: daemon.NewApp().Action,
		Flags:  daemon.NewApp().Flags,
	}
	if err := root.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
