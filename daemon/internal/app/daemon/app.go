package daemon

import (
	"context"

	"github.com/urfave/cli/v3"
)

func NewApp() *cli.Command {
	return &cli.Command{
		Name: "juneaud",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return nil
		},
	}
}
