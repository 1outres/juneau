package main

import (
	"github.com/1outres/juneau/daemon/internal/cni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cni.CmdAdd,
		Del:   cni.CmdDel,
		Check: cni.CmdCheck,
	}, version.All, "")
}
