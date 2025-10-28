package server

import (
	"context"

	"github.com/1outres/juneau/daemon/pkg/juneaupb"
)

type IPAMServer struct {
	juneaupb.UnimplementedIPAMServer
}

func NewIPAMServer() *IPAMServer {
	return &IPAMServer{}
}

func (*IPAMServer) Allocate(ctx context.Context, req *juneaupb.AllocateRequest) (*juneaupb.AllocateResponse, error) {
	return nil, nil
}
