package version

import (
	"fmt"
	"runtime"
)

// Build-time metadata populated via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info returns a human-readable build version summary.
func Info() string {
	return fmt.Sprintf("rotex %s (commit: %s, built: %s, %s/%s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
}
