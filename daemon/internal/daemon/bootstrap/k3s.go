package bootstrap

import (
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

func CopyLoopbackCNI(cniBinDir string) error {
	targetPath := filepath.Join(cniBinDir, "loopback")
	srcPath := "/var/lib/rancher/k3s/data/current/bin/loopback"

	if _, err := os.Stat(targetPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(srcPath); err != nil {
		if os.IsNotExist(err) {
			zap.S().Warnf("source loopback CNI binary does not exist at %s, skipping copy", srcPath)
			return nil
		}
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()

	if err := os.MkdirAll(cniBinDir, 0o755); err != nil {
		return err
	}

	dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		_ = dst.Close()
	}()

	if _, err = io.Copy(dst, src); err != nil {
		return err
	}
	zap.S().Infof("copied loopback CNI binary to %s", targetPath)
	return nil
}
