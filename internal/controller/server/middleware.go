package server

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"iptables-tool/internal/config"
	"iptables-tool/internal/controller/auth"
)

// policyCfg 策略/规则业务阈值(B5):newWebHandler 启动时从 config 一次性写入,
// 运行时只读(不并发写)。路由层读取,替代散落各文件的硬编码 const。
// 默认值 = 现状(见 config.Default()),运维可在 YAML 调整。
var policyCfg = config.Default().Policy

// requestLogger 结构化请求日志中间件(AOP,零侵入:B4)。
// 记录 method/path/status/耗时/用户,排查问题不再依赖前端复现。
// 不改变任何现有响应行为;logger 可注入便于测试(生产用 slog.Default)。
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		user := ""
		if u, ok := c.Get("user"); ok {
			if cu, ok := u.(auth.User); ok {
				user = cu.Username
			}
		}
		logger.Info("http",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"ms", time.Since(start).Milliseconds(),
			"user", user,
		)
	}
}
