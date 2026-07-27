// Package server 组装 Controller 的 Web (Gin) 和 gRPC 端点，管理生命周期。
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	"iptables-tool/internal/security"
)

// Server 持有 Web 和 gRPC 服务器及其共享依赖。
type Server struct {
	cfg      config.Config
	log      *slog.Logger
	db       *gorm.DB
	ca       *pki.CA
	stream   *stream.Service
	policy   *policy.Service
	comp     *compiler.Compiler
	co       *task.Coordinator
	sec      *security.SecureInterceptor
	http     *http.Server
	grpc     *grpc.Server
}

// New 从配置和共享 DB 句柄构建 Server。
func New(cfg config.Config, log *slog.Logger, db *gorm.DB) (*Server, error) {
	log.Info("config loaded", "disable_mtls", cfg.Server.GRPC.TLS.Disable)

	// 当 mTLS 禁用时，CA 可选
	var ca *pki.CA
	if !cfg.Server.GRPC.TLS.Disable {
		var err error
		ca, err = pki.LoadCA(cfg.CA.CertFile, cfg.CA.KeyFile)
		if err != nil {
			return nil, err
		}
	}

	// 根据配置决定是否加载 TLS 凭据
	var opts []grpc.ServerOption
	if !cfg.Server.GRPC.TLS.Disable {
		creds, err := loadServerTLS(cfg.Server.GRPC.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	}

	auditSink := audit.New(db)

	// 创建安全拦截器（集成 mTLS + 会话令牌 + HMAC + IP钉扎）
	hmacSecret := []byte(os.Getenv("MYFW_HMAC_SECRET"))
	if len(hmacSecret) == 0 {
		// 开发环境使用随机密钥，生产环境必须通过环境变量设置
		hmacSecret = make([]byte, 32)
		rand.Read(hmacSecret)
		log.Warn("using random HMAC secret; set MYFW_HMAC_SECRET in production")
	}

	secInterceptor := security.NewSecureInterceptor(security.SecureConfig{
		DisableTLS:       cfg.Server.GRPC.TLS.Disable,
		SessionTTL:       24 * time.Hour,
		HMACSecret:       hmacSecret,
		EnableIPPinning:  true,
		AntiReplayWindow: 300,
	}, log)

	// 使用安全拦截器替代原有的 authUnary/authStream
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			secInterceptor.UnaryServerInterceptor(),
			legacyAuthUnary(db, cfg.Server.GRPC.TLS.Disable),
		),
		grpc.ChainStreamInterceptor(
			secInterceptor.StreamServerInterceptor(),
			legacyAuthStream(db, cfg.Server.GRPC.TLS.Disable),
		),
	)

	grpcSrv := grpc.NewServer(opts...)
	// 注册服务
	regSvc := registration.New(db, ca, cfg.CA.AgentCertTTL, auditSink)
	myfwv1.RegisterRegistrationServer(grpcSrv, regSvc)

	streamSvc := stream.New(db, log, auditSink)
	myfwv1.RegisterAgentStreamServer(grpcSrv, streamSvc)

	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, log)

	// Web (Gin) REST 路由
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
		sec:    secInterceptor,
		grpc:   grpcSrv,
	}
	s.http = &http.Server{
		Addr:              cfg.Server.Web.Listen,
		Handler:           webHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// loadServerTLS 构建 mTLS 凭据。
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
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// bootstrapMethods 列出不需要客户端证书的 gRPC 方法。
var bootstrapMethods = map[string]bool{
	"/myfw.v1.Registration/Register": true,
}

// legacyAuthUnary 保留原有的数据库级认证检查（证书吊销、节点状态等）。
// 安全拦截器处理 mTLS + 会话层认证，这里做业务层二次校验。
func legacyAuthUnary(db *gorm.DB, disableMTLS bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkAuth(ctx, info.FullMethod, db, disableMTLS); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// legacyAuthStream 流式RPC的业务层认证。
func legacyAuthStream(db *gorm.DB, disableMTLS bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkAuth(ss.Context(), info.FullMethod, db, disableMTLS); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// checkAuth 业务层认证：验证证书是否被吊销、节点是否归档。
func checkAuth(ctx context.Context, method string, db *gorm.DB, disableMTLS bool) error {
	if bootstrapMethods[method] {
		return nil
	}
	if disableMTLS {
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
	return nil
}

// newWebHandler 构建 Gin 引擎。
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
	registerPolicyRoutes(r, policySvc, co, comp)
	registerAuditRoutes(r, auditSink)
	registerDashboardRoutes(r, db)
	registerIptablesRoutes(r, db)

	r.Static("/assets", "/var/www/myfw/assets")
	r.NoRoute(func(c *gin.Context) {
		c.File("/var/www/myfw/index.html")
	})

	return r
}

// BuildWebHandler 测试辅助：构建 Web handler 树。
func BuildWebHandler(db *gorm.DB, tokenTTL time.Duration) http.Handler {
	auditSink := audit.New(db)
	assets := asset.New(db, auditSink, tokenTTL)
	streamSvc := stream.New(db, slog.Default(), auditSink)
	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, slog.Default())
	return newWebHandler(db, assets, streamSvc, policySvc, co, comp, auditSink)
}

// BuildWebHandlerWithStream 测试辅助：注入共享的 stream.Service。
func BuildWebHandlerWithStream(db *gorm.DB, tokenTTL time.Duration, streamSvc *stream.Service) http.Handler {
	auditSink := audit.New(db)
	assets := asset.New(db, auditSink, tokenTTL)
	policySvc := policy.New(db)
	comp := compiler.New(db)
	co := task.NewCoordinator(db, streamSvc, comp, auditSink, slog.Default())
	return newWebHandler(db, assets, streamSvc, policySvc, co, comp, auditSink)
}

// Run 启动两个服务器并阻塞直到 ctx 取消。
func (s *Server) Run(ctx context.Context) error {
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
