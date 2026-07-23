package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// TODO：1.配置初始化
	// TODO：2.日志
	// TODO：3.数据库连接
	// TODO：4.其他初始化
	// TODO：5.启动服务

	r := gin.Default()

	// 测试路由
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	// 启动服务器
	r.Run(":8080")
}
