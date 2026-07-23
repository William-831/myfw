package server

import (
	"io"
	"log/slog"
)

// testLogger returns a discarding logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
