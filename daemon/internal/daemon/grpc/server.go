package grpc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type Server struct {
	grpcServer *grpc.Server
	cni        *CNIServer
}

func (s *Server) Start(udsPath string) error {
	if err := os.Remove(udsPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	lis, err := net.Listen("unix", udsPath)
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}
	if err := os.Chmod(udsPath, 0660); err != nil {
		return fmt.Errorf("chmod: %v", err)
	}

	go func() {
		zap.S().Infof("gRPC server listening on %s", udsPath)
		if err := s.grpcServer.Serve(lis); err != nil {
			zap.S().Fatalf("serve: %v", err)
		}
	}()

	return nil
}

func NewServer() *Server {
	s := &Server{
		grpcServer: grpc.NewServer(),
		cni:        newCNIServer(),
	}
	cnipb.RegisterCNIServer(s.grpcServer, s.cni)

	return s
}
