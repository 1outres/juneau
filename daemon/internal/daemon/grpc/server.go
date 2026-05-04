package grpc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/trace"
	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Server struct {
	grpcServer *grpc.Server
	cni        *CNIServer
	debug      *DebugServer

	mu       sync.Mutex
	lis      net.Listener
	udsPath  string
	stopOnce sync.Once
}

// SnapshotBacklog bounds per-session in-memory backlog the debug
// server keeps for late-attaching kubectl streams. 256 events covers
// the time between session start and the first WatchTrace call
// without becoming a memory hazard.
const SnapshotBacklog = 256

// SnapshotEvictInterval bounds how stale a session's snapshot
// backlog may stay after the session is gone.
const SnapshotEvictInterval = 30 * time.Second

func (s *Server) Run(ctx context.Context, udsPath string) error {
	if err := s.listen(udsPath); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		zap.S().Infof("gRPC server listening on %s", udsPath)
		errCh <- s.grpcServer.Serve(s.listener())
	}()

	select {
	case <-ctx.Done():
		s.Stop()
		err := <-errCh
		if errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		zap.L().Warn("gRPC server exited after context cancellation", zap.Error(err))
		return nil
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		s.Stop()
		return fmt.Errorf("gRPC serve: %w", err)
	}
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.debug != nil {
			s.debug.Stop()
		}
		s.mu.Lock()
		lis := s.lis
		udsPath := s.udsPath
		s.mu.Unlock()

		if lis != nil {
			_ = lis.Close()
		}

		done := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.grpcServer.Stop()
		}

		if udsPath != "" {
			_ = os.Remove(udsPath)
		}
	})
}

func (s *Server) listen(udsPath string) error {
	if err := removeStaleSocket(udsPath); err != nil {
		return err
	}

	lis, err := net.Listen("unix", udsPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(udsPath, 0660); err != nil {
		_ = lis.Close()
		return fmt.Errorf("chmod: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.lis = lis
	s.udsPath = udsPath
	return nil
}

func (s *Server) listener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lis
}

func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat socket: %w", err)
	}

	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path exists and is not a unix socket: %s", path)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

// NewServer constructs the gRPC server. CNI is always registered;
// the debug surface is registered only when the trace plane provides
// a Bus and Store (i.e. the dataplane has finished loading BPF maps).
func NewServer(client client.Client, traceBus *trace.Bus, traceStore *trace.Store, nodeName string) *Server {
	s := &Server{
		grpcServer: grpc.NewServer(),
		cni:        newCNIServer(client),
	}
	cnipb.RegisterCNIServer(s.grpcServer, s.cni)

	if traceBus != nil && traceStore != nil {
		s.debug = NewDebugServer(traceBus, traceStore, nodeName, SnapshotBacklog)
		debugpb.RegisterDebugServer(s.grpcServer, s.debug)
	}

	return s
}

// StartBackground starts background goroutines (snapshot collector,
// evictor) tied to ctx. Safe to call when the debug server is not
// configured.
func (s *Server) StartBackground(ctx context.Context) {
	if s.debug == nil {
		return
	}
	s.debug.Start(ctx)
	s.debug.startSnapshotEvictor(ctx, SnapshotEvictInterval)
}
