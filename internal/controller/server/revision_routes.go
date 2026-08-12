package server

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"iptables-tool/internal/controller/revision"
	"iptables-tool/internal/controller/task"
	"iptables-tool/internal/model"
)

// registerRevisionRoutes 注册节点规则库版本档案(计划三)路由:
//   - GET  /api/v1/nodes/:id/revisions          历史版本列表(新 -> 旧)
//   - POST /api/v1/nodes/:id/revisions/:no/rollback 回滚到指定版本
//
// 回滚语义:回滚前自动归档当前版本(便于"撤销回滚"),历史规则集直接下发、
// 不重新编译,走正常保护期(超时由 Agent 自身快照回退)。回滚是临时排障手段,
// 完成后实例 applied 全置 false(规则已偏离当前定义,需重新下发收敛)。
func registerRevisionRoutes(r gin.IRouter, revSvc *revision.Service, co *task.Coordinator) {
	// 注意:节点段参数用 :id 与既有 node 路由一致(Gin 不允许同段位不同通配符名)。
	g := r.Group("/api/v1/nodes/:id/revisions")

	g.GET("", func(c *gin.Context) {
		nodeID := c.Param("id")
		revs, err := revSvc.List(c.Request.Context(), nodeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"revisions": revs})
	})

	g.POST("/:rev_no/rollback", func(c *gin.Context) {
		nodeID := c.Param("id")
		revNo, err := strconv.ParseInt(c.Param("rev_no"), 10, 64)
		if err != nil || revNo <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad revision number"})
			return
		}
		ctx := c.Request.Context()
		// 1. 归档当前版本(source=rollback):回滚是排障手段,先留档此刻状态,
		//    若回滚效果不佳可再"回滚到本版本"(撤销回滚)。
		if err := revSvc.Archive(ctx, nodeID, "rollback", "", "回滚前归档(当前版本)"); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 2. 读取历史版本规则集
		rs, err := revSvc.Load(ctx, nodeID, revNo)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		// 3. 下发回滚任务(历史规则集直接下发,不重新编译)
		tk, err := co.SubmitRuleSet(ctx, nodeID, rs, task.SubmitOpts{
			Author: actor(c), AutoApprove: true, Scene: model.AuditSceneRevisionRollback,
		})
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "task": tk})
			return
		}
		c.JSON(http.StatusOK, gin.H{"task": tk})
	})
}
