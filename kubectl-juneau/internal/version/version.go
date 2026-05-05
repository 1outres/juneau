// Package version centralises the build-time identity of the kubectl
// plugin so command code does not have to know about ldflags wiring.
//
// Values are populated by `go build -ldflags="-X
// github.com/1outres/juneau/kubectl-juneau/internal/version.gitCommit=..."`.
// When unset (e.g. `go run`, `go test`), Get falls back to runtime/debug
// build info so a binary built without ldflags still reports something
// truthful.
package version

import (
	"runtime"
	"runtime/debug"
)

var (
	// Set via -ldflags. Leave empty to fall through to build-info.
	gitCommit = ""
	gitTag    = ""
	buildDate = ""
)

// Info captures everything we surface in `kubectl juneau version`. It is
// also serialisable so -o json/yaml is a one-liner.
type Info struct {
	GitTag    string `json:"gitTag,omitempty" yaml:"gitTag,omitempty"`
	GitCommit string `json:"gitCommit,omitempty" yaml:"gitCommit,omitempty"`
	BuildDate string `json:"buildDate,omitempty" yaml:"buildDate,omitempty"`
	GoVersion string `json:"goVersion" yaml:"goVersion"`
	Platform  string `json:"platform" yaml:"platform"`
}

// Get returns the populated Info, filling missing ldflag-based fields
// from runtime/debug build info when available.
func Get() Info {
	info := Info{
		GitTag:    gitTag,
		GitCommit: gitCommit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if info.GitCommit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					info.GitCommit = s.Value
				}
				if s.Key == "vcs.time" && info.BuildDate == "" {
					info.BuildDate = s.Value
				}
			}
		}
	}
	return info
}
