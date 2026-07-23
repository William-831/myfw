package server

import (
	"context"
	"io"
	"log/slog"

	"google.golang.org/grpc"

	"iptables-tool/internal/controller/stream"
)

// GRPCServerForTest returns the underlying *grpc.Server so external test
// packages can bind their own listener and Serve() it. Not part of the
// stable API — this exists so bootstrap_test can drive a full stack.
func (s *Server) GRPCServerForTest() *grpc.Server { return s.grpc }

// StreamForTest returns the shared *stream.Service so external tests can
// build a Web handler that dispatches onto the same registry the gRPC server
// receives connections into. Not part of the stable API.
func (s *Server) StreamForTest() *stream.Service { return s.stream }

// StartCoordinatorForTest starts the Coordinator's background loops (result
// subscriber, recovery, confirm-wait timers) without starting the HTTP/gRPC
// listeners. Only for tests. Not part of the stable API.
func (s *Server) StartCoordinatorForTest(ctx context.Context) { s.co.Start(ctx) }

// TestLogger returns a slog.Logger that discards output; useful when a caller
// doesn't want test logs to pollute stdout.
func TestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
