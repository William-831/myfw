// Package server wires together the Controller's Web (Gin) and gRPC endpoints
// and manages their lifecycle. Business handlers are registered in later
// milestones; M2 provides the skeleton and M3 adds mTLS enforcement +
// registration/asset services. See docs/development-plan.md § M2/§ M3.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/config"
	"iptables-tool/internal/controller/asset"
	"iptables-tool/internal/controller/auth"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/controller/registration"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/controller/task"
	"iptables-tool/internal/model"
	"iptables-tool/internal/pki"
)

// Server owns the Web and gRPC servers and their shared dependencies.
type Server struct {
	cfg    config.Config
	log    *slog.Logger
	db     *gorm.DB
	ca     *pki.CA
	stream *stream.Service
	policy *policy.Service
	comp   *compiler.Compiler
	co     *task.Coordinator
	http   *http.Server
	grpc   *grpc.Server
}

// New constructs a Server from config plus the shared DB handle.
func New(cfg config.Config, log *slog.Logger, db *gorm.DB) (*Server, error) {
	ca, err := pki.LoadCA(cfg.CA.CertFile, cfg.CA.KeyFile)
	if err != nil {
		return nil, err
	}

	creds, err := loadServerTLS(cfg.Server.GRPC.TLS)
	if err != nil {
		return nil, err
	}

	auditSink := audit.New(db)

	grpcSrv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(authUnary(db)),
		grpc.StreamInterceptor(authStream(db)),
	)
	// Register services.
	regSvc := registration.New(db, ca, cfg.CA.AgentCertTTL, auditSink)
	myfwv1.RegisterRegistrationServer(grpcSrv, regSvc)

	streamSvc := stream.New(db, log, auditSink)
	myfwv1.RegisterAgentStreamServer(grpcSrv, streamSvc)

	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, log)

	// Web (Gin) with REST admin routes.
	assetH := asset.New(db, auditSink, cfg.Bootstrap.TokenTTL)
	webHandler := newWebHandler(db, assetH, streamSvc, policySvc, co, comp, auditSink)

	s := &Server{
		cfg:    cfg,
		log:    log,
		db:     db,
		ca:     ca,
		stream: streamSvc,
		policy: policySvc,
		comp:   comp,
		co:     co,
		grpc:   grpcSrv,
	}
	s.http = &http.Server{
		Addr:              cfg.Server.Web.Listen,
		Handler:           webHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// loadServerTLS builds mTLS credentials. Client certificates are VERIFIED
// when presented, but not required at TLS handshake time — that lets a fresh
// Agent call Registration.Register (which has no client cert yet). All other
// RPCs are guarded by authUnary/authStream which reject missing certs.
func loadServerTLS(t config.TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("server: load server keypair: %w", err)
	}
	caPEM, err := os.ReadFile(t.CAFile)
	if err != nil {
		return nil, fmt.Errorf("server: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("server: no valid certificates in %s", t.CAFile)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven, // handshake-layer TOFU allowed
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// bootstrapMethods lists gRPC methods that may be called WITHOUT a client
// certificate. Everything else requires an mTLS-authenticated peer bound to
// a live node record.
var bootstrapMethods = map[string]bool{
	"/myfw.v1.Registration/Register": true,
}

// authUnary enforces the certificate-binding contract on all unary RPCs.
func authUnary(db *gorm.DB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkAuth(ctx, info.FullMethod, db); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// authStream enforces the same rules on server-streaming/bidirectional RPCs.
func authStream(db *gorm.DB) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkAuth(ss.Context(), info.FullMethod, db); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// checkAuth is the shared authorization step. For bootstrap methods it is a
// no-op (the RPC itself validates the token); for every other method it:
//  1. Requires a verified client certificate.
//  2. Extracts the node id from the certificate's URI SAN / CN.
//  3. Looks up the persisted Certificate row by fingerprint and confirms it
//     is not revoked and belongs to that same node id.
//  4. Confirms the node exists and is not ARCHIVED.
func checkAuth(ctx context.Context, method string, db *gorm.DB) error {
	if bootstrapMethods[method] {
		return nil
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "not a TLS connection")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	cert := tlsInfo.State.VerifiedChains[0][0]

	nodeID, err := pki.NodeIDFromCert(cert)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	fp := pki.Fingerprint(cert)

	var row model.Certificate
	if err := db.WithContext(ctx).Where("fingerprint = ?", fp).First(&row).Error; err != nil {
		return status.Error(codes.Unauthenticated, "unknown certificate")
	}
	if row.Revoked {
		return status.Error(codes.Unauthenticated, "certificate revoked")
	}
	if row.NodeID != nodeID {
		return status.Error(codes.Unauthenticated, "certificate/node id mismatch")
	}
	var node model.Node
	if err := db.WithContext(ctx).Where("id = ?", nodeID).First(&node).Error; err != nil {
		return status.Error(codes.Unauthenticated, "unknown node")
	}
	if node.Status == model.NodeStatusArchived {
		return status.Error(codes.PermissionDenied, "node archived")
	}
	// PENDING/ACTIVE/OFFLINE all reach handlers; individual handlers may still
	// gate on status (e.g. only ACTIVE receives ApplyTasks).
	_ = strings.TrimSpace // keep the strings import for future header parsing
	return nil
}

// newWebHandler builds the Gin engine with health + admin REST routes.
func newWebHandler(db *gorm.DB, assets *asset.Handler, streamSvc *stream.Service, policySvc *policy.Service, co *task.Coordinator, comp *compiler.Compiler, auditSink *audit.Sink) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.GET("/metrics", prometheusHandler())

	authH := auth.New(db)
	authH.Register(r)

	assets.Register(r)
	registerNodeRoutes(r, db)
	registerTaskRoutes(r, streamSvc)
	registerTaskLifecycleRoutes(r, co)
	registerApprovalRoutes(r, co)
	registerPolicyRoutes(r, policySvc, co, comp)
	registerAuditRoutes(r, auditSink)
	registerDashboardRoutes(r, db)

	r.Static("/assets", "/var/www/myfw/assets")
	r.NoRoute(func(c *gin.Context) {
		c.File("/var/www/myfw/index.html")
	})

	return r
}

// BuildWebHandler is a test-facing helper that constructs the same handler
// tree the server serves at /, without touching listeners. Tests use it with
// httptest to exercise REST routes against a real DB.
func BuildWebHandler(db *gorm.DB, tokenTTL time.Duration) http.Handler {
	auditSink := audit.New(db)
	assets := asset.New(db, auditSink, tokenTTL)
	streamSvc := stream.New(db, slog.Default(), auditSink)
	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, slog.Default())
	return newWebHandler(db, assets, streamSvc, policySvc, co, comp, auditSink)
}

// BuildWebHandlerWithStream is the same but lets the caller inject a shared
// stream.Service so REST-issued apply tasks land on the same registry the
// gRPC server uses. This is what tests use for end-to-end.
func BuildWebHandlerWithStream(db *gorm.DB, tokenTTL time.Duration, streamSvc *stream.Service) http.Handler {
	auditSink := audit.New(db)
	assets := asset.New(db, auditSink, tokenTTL)
	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, slog.Default())
	return newWebHandler(db, assets, streamSvc, policySvc, co, comp, auditSink)
}

// Run starts both servers and blocks until ctx is cancelled, then shuts down
// gracefully.
func (s *Server) Run(ctx context.Context) error {
	// M7: start the task coordinator's background loops (result subscriber,
	// startup recovery of orphaned tasks, confirm-wait timers).
	s.co.Start(ctx)

	grpcLn, err := net.Listen("tcp", s.cfg.Server.GRPC.Listen)
	if err != nil {
		return fmt.Errorf("server: listen grpc %s: %w", s.cfg.Server.GRPC.Listen, err)
	}

	errCh := make(chan error, 2)

	go func() {
		s.log.Info("gRPC listening", "addr", s.cfg.Server.GRPC.Listen)
		if err := s.grpc.Serve(grpcLn); err != nil {
			errCh <- fmt.Errorf("grpc serve: %w", err)
		}
	}()

	go func() {
		s.log.Info("Web listening", "addr", s.cfg.Server.Web.Listen)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("web serve: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.log.Info("shutdown signal received")
	case err := <-errCh:
		s.log.Error("server error", "err", err)
		s.shutdown()
		return err
	}

	s.shutdown()
	return nil
}

func (s *Server) shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Stop the coordinator first so in-flight result handling drains before
	// we tear down the gRPC server (which hosts the AgentStream).
	s.co.Stop()
	if err := s.http.Shutdown(shutdownCtx); err != nil {
		s.log.Warn("web shutdown", "err", err)
	}
	s.grpc.GracefulStop()
	s.log.Info("servers stopped")
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func registerAuditRoutes(r *gin.Engine, auditSink *audit.Sink) {
	r.GET("/api/audit/logs", func(c *gin.Context) {
		action := c.Query("action")
		nodeID := c.Query("node_id")
		limitStr := c.DefaultQuery("limit", "10")
		offsetStr := c.DefaultQuery("offset", "0")

		limit, _ := strconv.Atoi(limitStr)
		offset, _ := strconv.Atoi(offsetStr)

		logs, total, err := auditSink.Query(c.Request.Context(), action, nodeID, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": logs, "total": total})
	})

	r.GET("/api/audit/export", func(c *gin.Context) {
		action := c.Query("action")
		nodeID := c.Query("node_id")

		logs, _, err := auditSink.Query(c.Request.Context(), action, nodeID, 10000, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")

		w := csv.NewWriter(c.Writer)
		w.Write([]string{"ID", "Actor", "Action", "NodeID", "Detail", "CreatedAt"})
		for _, log := range logs {
			w.Write([]string{
				fmt.Sprintf("%d", log.ID),
				log.Actor,
				log.Action,
				log.NodeID,
				log.Detail,
				log.CreatedAt.Format(time.RFC3339),
			})
		}
		w.Flush()
	})
}

func registerNodeRoutes(r *gin.Engine, db *gorm.DB) {
	g := r.Group("/api/v1/nodes")
	g.GET("/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node model.Node
		if err := db.Preload("Capability").Where("id = ?", id).First(&node).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
			return
		}
		c.JSON(http.StatusOK, node)
	})
	g.PUT("/:id", func(c *gin.Context) {
		id := c.Param("id")
		var body struct {
			Labels []string `json:"labels"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		labelsJSON, _ := json.Marshal(body.Labels)
		if err := db.Model(&model.Node{}).Where("id = ?", id).Update("labels", string(labelsJSON)).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var node model.Node
		db.Preload("Capability").Where("id = ?", id).First(&node)
		c.JSON(http.StatusOK, node)
	})
	g.DELETE("/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := db.Model(&model.Node{}).Where("id = ?", id).Update("status", model.NodeStatusArchived).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	})
}

func registerApprovalRoutes(r *gin.Engine, co *task.Coordinator) {
	g := r.Group("/api/approvals")
	g.GET("", func(c *gin.Context) {
		status := c.Query("status")
		if status == "" {
			status = string(model.TaskPendingApproval)
		}
		list, err := co.List(c.Request.Context(), status)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": list, "total": len(list)})
	})
	g.POST("/:id/approve", func(c *gin.Context) {
		t, err := co.Approve(c.Request.Context(), c.Param("id"), actor(c), 5*time.Minute)
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, t)
	})
	g.POST("/:id/reject", func(c *gin.Context) {
		var body struct {
			Reason string `json:"reason"`
		}
		_ = c.ShouldBindJSON(&body)
		t, err := co.Reject(c.Request.Context(), c.Param("id"), actor(c), body.Reason)
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, t)
	})
}

func registerDashboardRoutes(r *gin.Engine, db *gorm.DB) {
	r.GET("/api/dashboard/stats", func(c *gin.Context) {
		var nodeCount, activeNodeCount, pendingNodeCount int64
		var policyCount, activePolicyCount int64
		var pendingTaskCount int64

		db.Model(&model.Node{}).Count(&nodeCount)
		db.Model(&model.Node{}).Where("status = ?", model.NodeStatusActive).Count(&activeNodeCount)
		db.Model(&model.Node{}).Where("status = ?", model.NodeStatusPending).Count(&pendingNodeCount)

		db.Model(&model.Policy{}).Count(&policyCount)
		db.Model(&model.Policy{}).Where("enabled = ?", true).Count(&activePolicyCount)

		db.Model(&model.Task{}).Where("status = ?", model.TaskPendingApproval).Count(&pendingTaskCount)

		c.JSON(http.StatusOK, gin.H{
			"node_count":          nodeCount,
			"active_node_count":   activeNodeCount,
			"pending_node_count":  pendingNodeCount,
			"policy_count":        policyCount,
			"active_policy_count": activePolicyCount,
			"pending_task_count":  pendingTaskCount,
		})
	})
}
