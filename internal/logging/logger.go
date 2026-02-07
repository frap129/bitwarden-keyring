// Package logging provides a shared structured logger for the application.
package logging

import (
	"log/slog"
	"os"
)

// L is the package-level logger used throughout the application.
// It defaults to slog.Default() and is reconfigured by Setup().
var L = slog.Default()

// Setup configures the package-level logger based on the debug flag.
// When debug is true, the log level is set to Debug; otherwise Info.
func Setup(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	L = slog.New(handler)
}
