package cni

import (
	"context"

	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func (c *Cni) CmdDel(ctx context.Context) error {
	vethHostName := c.vethHostName()

	vethHost, err := netlink.LinkByName(vethHostName)
	if _, ok := err.(netlink.LinkNotFoundError); !ok && err != nil {
		zap.L().Error("failed to lookup veth", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to lookup veth",
			Details: err.Error(),
		}
	} else if err == nil {
		if err := netlink.LinkDel(vethHost); err != nil {
			zap.L().Error("failed to delete veth", zap.Error(err))
			return &types.Error{
				Code:    types.ErrTryAgainLater,
				Msg:     "Failed to delete veth",
				Details: err.Error(),
			}
		}
		zap.L().Info("veth deleted", zap.String("veth", vethHost.Attrs().Name))
	}

	releaseRes, err := c.IPAMClient.Release(ctx, &juneaupb.ReleaseRequest{
		Id: &juneaupb.CNIIdentity{
			PodNamespace: c.PodNamespace,
			PodName:      c.PodName,
			PodUid:       c.PodUID,
			ContainerId:  c.ContainerID,
			IfName:       c.IfName,
		},
	})
	if err != nil {
		zap.L().Error("failed to release IP", zap.Error(err))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "Failed to release IP",
			Details: err.Error(),
		}
	}
	if !releaseRes.Success {
		zap.L().Error("IP release was not successful", zap.String("message", releaseRes.Error.Message))
		return &types.Error{
			Code:    types.ErrTryAgainLater,
			Msg:     "IP release was not successful",
			Details: releaseRes.Error.Message,
		}
	}

	zap.L().Info("IP released successfully")

	return nil
}
