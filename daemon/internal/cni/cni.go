package cni

import "github.com/1outres/juneau/daemon/pkg/juneaupb"

type Cni struct {
	IPAMClient juneaupb.IPAMClient

	PodNamespace string
	PodName      string
	PodUID       string
	ContainerID  string
	Netns        string
	IfName       string

	CNIVersion string
}

func (c *Cni) vethHostName() string {
	return c.IfName + "+" + c.ContainerID[0:10]
}

func (c *Cni) vethPeerName() string {
	return "tmp+" + c.IfName + "+" + c.ContainerID[0:6]
}
