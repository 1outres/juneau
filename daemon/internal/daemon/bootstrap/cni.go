package bootstrap

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/1outres/juneau/daemon/bin"
)

const cniConfigTemplate = `{
  "name": "juneau-net",
  "type": "juneau",
  "cniVersion": "1.1.0",
  "daemon": {
    "socket": "{{ .socket }}",
    "timeoutMs": {{ .timeoutMs }}
  }
}
`

func InstallCNIBinary(cniBinDir string) error {
	targetPath := filepath.Join(cniBinDir, "juneau")

	return installFile(targetPath, 0o755, bin.CNIBinary)
}

func InstallCNIConfig(cniConfDir string, udsPath string, timeoutMs int) error {
	targetPath := filepath.Join(cniConfDir, "juneau.conf")

	tmpl, err := template.New("cni-config").Parse(cniConfigTemplate)
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"socket":    udsPath,
		"timeoutMs": timeoutMs,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}

	return installFile(targetPath, 0o644, buf.Bytes())
}

func installFile(dstPath string, mode fs.FileMode, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}

	tmp := filepath.Join(filepath.Dir(dstPath), fmt.Sprintf(".%s.tmp-%d", filepath.Base(dstPath), time.Now().UnixNano()))
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return nil
}
