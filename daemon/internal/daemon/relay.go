package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/urfave/cli/v3"
)

// NewRelayApp returns the `juneaud relay` subcommand: a tiny stdio
// ↔ unix-socket bridge used by `kubectl juneau trace` to tunnel
// gRPC traffic over `kubectl exec` without requiring socat in the
// daemon image.
//
// Behaviour matches `socat - UNIX-CONNECT:<path>` — read from stdin,
// write to the socket; read from the socket, write to stdout. The
// command exits when either side closes; failures on the socket-
// connect path return non-zero.
func NewRelayApp() *cli.Command {
	return &cli.Command{
		Name:      "relay",
		Usage:     "Bridge stdin/stdout to a unix socket (used by kubectl juneau trace)",
		ArgsUsage: "<uds-path>",
		Action: func(_ context.Context, cmd *cli.Command) error {
			udsPath := cmd.Args().First()
			if udsPath == "" {
				return fmt.Errorf("uds path is required")
			}
			conn, err := net.Dial("unix", udsPath)
			if err != nil {
				return fmt.Errorf("dial %s: %w", udsPath, err)
			}
			defer func() {
				_ = conn.Close()
			}()

			errCh := make(chan error, 2)
			go func() {
				_, err := io.Copy(conn, os.Stdin)
				errCh <- err
				if uconn, ok := conn.(*net.UnixConn); ok {
					_ = uconn.CloseWrite()
				}
			}()
			go func() {
				_, err := io.Copy(os.Stdout, conn)
				errCh <- err
				_ = os.Stdout.Close()
			}()

			// Either direction closing is normal end-of-stream; we
			// only fail if the first side reports an unexpected
			// error.
			err = <-errCh
			if err != nil && err != io.EOF {
				return err
			}
			return nil
		},
	}
}
