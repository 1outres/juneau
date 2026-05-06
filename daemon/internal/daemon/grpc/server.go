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

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/mapinventory"
	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/trace"
	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"github.com/1outres/juneau/daemon/pkg/debugpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DefaultDebugTCPAddr is the loopback bind for the debug-only gRPC
// server. kubectl-juneau reaches it via `kubectl port-forward`, so
// 127.0.0.1 is sufficient — no in-cluster TCP path needs it.
const DefaultDebugTCPAddr = "127.0.0.1:9089"

// SnapshotBacklog bounds per-session in-memory backlog the debug
// server keeps for late-attaching kubectl streams. 256 events covers
// the time between session start and the first WatchTrace call
// without becoming a memory hazard.
const SnapshotBacklog = 256

// SnapshotEvictInterval bounds how stale a session's snapshot
// backlog may stay after the session is gone.
const SnapshotEvictInterval = 30 * time.Second

// Server hosts two independent gRPC surfaces:
//   - CNI on a unix domain socket. kubelet's CRI-driven CNI plugin
//     dials this; the path is part of the kubelet contract and
//     cannot move.
//   - Debug on a localhost TCP port. kubectl-juneau reaches it via
//     port-forward; keeping it off the UDS lets us register it as a
//     standard k8s.io/client-go portforward target without dragging
//     a custom relay into the daemon image.
//
// Each surface owns its own *grpc.Server so a slow / hung CNI client
// cannot stall debug streams (and vice versa) — they share nothing
// except the underlying handler implementations.
type Server struct {
	cniServer   *grpc.Server
	debugServer *grpc.Server

	cni   *CNIServer
	debug *DebugServer

	mu        sync.Mutex
	cniLis    net.Listener
	debugLis  net.Listener
	udsPath   string
	debugAddr string
	stopOnce  sync.Once
}

// Run starts both gRPC servers and blocks until ctx is cancelled or
// either surface returns an error. The two servers run on
// independent goroutines so a faulty surface only takes itself down.
func (s *Server) Run(ctx context.Context, udsPath string) error {
	if err := s.listenUDS(udsPath); err != nil {
		return err
	}
	if s.debugServer != nil {
		if err := s.listenDebugTCP(s.debugAddr); err != nil {
			_ = s.cniLis.Close()
			return err
		}
	}

	cniErrCh := make(chan error, 1)
	go func() {
		zap.S().Infof("gRPC (CNI) listening on %s", udsPath)
		cniErrCh <- s.cniServer.Serve(s.cniLis)
	}()

	debugErrCh := make(chan error, 1)
	if s.debugServer != nil {
		go func() {
			zap.S().Infof("gRPC (debug) listening on %s", s.debugAddr)
			debugErrCh <- s.debugServer.Serve(s.debugLis)
		}()
	} else {
		// Closed channel never fires — keeps select{} below uniform.
		close(debugErrCh)
	}

	select {
	case <-ctx.Done():
		s.Stop()
		drainServeErr(<-cniErrCh, "CNI")
		if s.debugServer != nil {
			drainServeErr(<-debugErrCh, "debug")
		}
		return nil
	case err := <-cniErrCh:
		if isServeShutdown(err) {
			return nil
		}
		s.Stop()
		return fmt.Errorf("gRPC CNI serve: %w", err)
	case err := <-debugErrCh:
		if !s.hasDebugServer() {
			return nil
		}
		if isServeShutdown(err) {
			return nil
		}
		s.Stop()
		return fmt.Errorf("gRPC debug serve: %w", err)
	}
}

func (s *Server) hasDebugServer() bool { return s.debugServer != nil }

// Stop tears down both servers + their listeners. Idempotent; safe to
// call from multiple goroutines.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.debug != nil {
			s.debug.Stop()
		}
		s.mu.Lock()
		cniLis := s.cniLis
		debugLis := s.debugLis
		udsPath := s.udsPath
		s.mu.Unlock()

		if cniLis != nil {
			_ = cniLis.Close()
		}
		if debugLis != nil {
			_ = debugLis.Close()
		}

		stopGraceful(s.cniServer)
		if s.debugServer != nil {
			stopGraceful(s.debugServer)
		}

		if udsPath != "" {
			_ = os.Remove(udsPath)
		}
	})
}

func (s *Server) listenUDS(udsPath string) error {
	if err := removeStaleSocket(udsPath); err != nil {
		return err
	}
	lis, err := net.Listen("unix", udsPath)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(udsPath, 0660); err != nil {
		_ = lis.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	s.mu.Lock()
	s.cniLis = lis
	s.udsPath = udsPath
	s.mu.Unlock()
	return nil
}

func (s *Server) listenDebugTCP(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	s.mu.Lock()
	s.debugLis = lis
	// Capture the actual addr in case caller passed :0 — useful in
	// tests; in production DefaultDebugTCPAddr is already concrete.
	s.debugAddr = lis.Addr().String()
	s.mu.Unlock()
	return nil
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

func isServeShutdown(err error) bool {
	return errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed)
}

func drainServeErr(err error, who string) {
	if err == nil || isServeShutdown(err) {
		return
	}
	zap.L().Warn("gRPC server exited after context cancellation", zap.String("which", who), zap.Error(err))
}

func stopGraceful(srv *grpc.Server) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		srv.Stop()
	}
}

// ServerConfig bundles construction-time options for NewServer so
// new transport knobs do not become positional-arg churn.
type ServerConfig struct {
	Client     client.Client
	TraceBus   *trace.Bus
	TraceStore *trace.Store
	// MapInventory backs the ListBPFMaps / DumpBPFMap RPCs. Optional;
	// the RPCs return FailedPrecondition when nil.
	MapInventory *mapinventory.Inventory
	NodeName     string
	// DebugTCPAddr binds the debug-only gRPC server. Empty disables
	// the debug surface entirely (useful when trace state is not
	// available or the operator wants to lock the daemon down).
	DebugTCPAddr string
}

// NewServer constructs both gRPC servers. CNI is always registered
// on the UDS server; the debug surface is registered on the TCP
// server only when the trace plane is available and a TCP addr is
// configured.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		cniServer: grpc.NewServer(),
		cni:       newCNIServer(cfg.Client),
	}
	cnipb.RegisterCNIServer(s.cniServer, s.cni)

	if cfg.TraceBus != nil && cfg.TraceStore != nil && cfg.DebugTCPAddr != "" {
		s.debugServer = grpc.NewServer()
		s.debug = NewDebugServer(cfg.TraceBus, cfg.TraceStore, cfg.NodeName, SnapshotBacklog)
		if cfg.MapInventory != nil {
			s.debug.SetMapInventory(cfg.MapInventory)
		}
		debugpb.RegisterDebugServer(s.debugServer, s.debug)
		s.debugAddr = cfg.DebugTCPAddr
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
