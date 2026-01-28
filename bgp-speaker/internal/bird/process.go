package bird

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	DefaultConfigPath  = "/etc/bird/bird.conf"
	DefaultControlPath = "/var/run/bird.ctl"
	DefaultBirdPath    = "bird"
	DefaultBirdcPath   = "birdc"
)

type ProcessOptions struct {
	BirdPath    string
	BirdcPath   string
	ConfigPath  string
	ControlPath string
}

type ProcessManager struct {
	birdPath    string
	birdcPath   string
	configPath  string
	controlPath string

	mu      sync.Mutex
	cmd     *exec.Cmd
	doneCh  chan error
	running bool
	exitCh  chan error
}

func NewProcessManager(opts ProcessOptions) *ProcessManager {
	if opts.BirdPath == "" {
		opts.BirdPath = DefaultBirdPath
	}
	if opts.BirdcPath == "" {
		opts.BirdcPath = DefaultBirdcPath
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}
	if opts.ControlPath == "" {
		opts.ControlPath = DefaultControlPath
	}
	return &ProcessManager{
		birdPath:    opts.BirdPath,
		birdcPath:   opts.BirdcPath,
		configPath:  opts.ConfigPath,
		controlPath: opts.ControlPath,
		exitCh:      make(chan error, 1),
	}
}

func (p *ProcessManager) ConfigPath() string {
	return p.configPath
}

func (p *ProcessManager) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	cmd := exec.Command(p.birdPath, "-f", "-c", p.configPath, "-s", p.controlPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		p.mu.Unlock()
		return err
	}

	doneCh := make(chan error, 1)
	p.cmd = cmd
	p.doneCh = doneCh
	p.running = true
	p.mu.Unlock()

	go func() {
		err := cmd.Wait()
		doneCh <- err
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
		select {
		case p.exitCh <- err:
		default:
		}
		if err != nil {
			zap.S().Warnw("bird exited", "error", err)
		} else {
			zap.S().Infow("bird exited")
		}
	}()

	return nil
}

func (p *ProcessManager) Reload(ctx context.Context) error {
	const (
		retryCount   = 4
		retryBaseDur = 100 * time.Millisecond
	)

	var lastErr error
	for i := 0; i <= retryCount; i++ {
		if i > 0 {
			wait := retryBaseDur * time.Duration(1<<(i-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		cmd := exec.CommandContext(ctx, p.birdcPath, "-s", p.controlPath, "configure")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			lastErr = err
			if i < retryCount {
				zap.S().Debugw("birdc configure failed; retrying", "error", err, "attempt", i+1)
				continue
			}
			zap.S().Warnw("birdc configure failed", "error", err)
			return err
		}
		return nil
	}

	return lastErr
}

func (p *ProcessManager) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *ProcessManager) Stop(ctx context.Context) error {
	p.mu.Lock()
	cmd := p.cmd
	doneCh := p.doneCh
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		if err := cmd.Process.Kill(); err != nil {
			return errors.Join(ctx.Err(), err)
		}
		return ctx.Err()
	case err := <-doneCh:
		return err
	}
}

func (p *ProcessManager) Wait(ctx context.Context) error {
	p.mu.Lock()
	doneCh := p.doneCh
	p.mu.Unlock()

	if doneCh == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-doneCh:
		return err
	}
}

func (p *ProcessManager) WaitForExit(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.Wait(ctx)
}

func (p *ProcessManager) ExitCh() <-chan error {
	return p.exitCh
}

func (p *ProcessManager) WaitForControlSocket(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}

	for {
		if _, err := os.Stat(p.controlPath); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (p *ProcessManager) EnsureControlDir() error {
	return os.MkdirAll(filepath.Dir(p.controlPath), 0o755)
}
