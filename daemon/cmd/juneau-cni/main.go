package main

import (
	"log"
	"os"

	"github.com/1outres/juneau/daemon/internal/cni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

func main() {
	if err := cni.Init(); err != nil {
		e := &types.Error{
			Code: types.ErrInternal,
			Msg: "Failed to init",
			Details: err.Error(),
		}
		if err := e.Print(); err != nil {
			log.Print("Error writing error JSON to stdout: ", err)
		}
		os.Exit(1)
	}

	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cni.CmdAdd,
		Del:   cni.CmdDel,
		Check: cni.CmdCheck,
	}, version.All, "")
}
