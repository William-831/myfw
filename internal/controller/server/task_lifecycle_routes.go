package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"iptables-tool/internal/controller/task"
)

// registerTaskLifecycleRoutes mounts M7's approval/confirm endpoints. These
// operate on Tasks that Submit created; the older ad-hoc M5 /nodes/:id/apply
// path still exists in task_routes.go and is not on this lifecycle.
func registerTaskLifecycleRoutes(r gin.IRouter, co *task.Coordinator) {
	g := r.Group("/api/v1/tasks")
	g.GET("", func(c *gin.Context) { listTasks(c, co) })
	g.GET("/:id", func(c *gin.Context) { getTask(c, co) })
	g.POST("/:id/approve", func(c *gin.Context) { approveTask(c, co) })
	g.POST("/:id/reject", func(c *gin.Context) { rejectTask(c, co) })
	g.POST("/:id/confirm", func(c *gin.Context) { confirmTask(c, co) })
}

func listTasks(c *gin.Context, co *task.Coordinator) {
	status := c.Query("status")
	list, err := co.List(c.Request.Context(), status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": list})
}

func getTask(c *gin.Context, co *task.Coordinator) {
	t, err := co.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondTaskErr(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

type approveReq struct {
	ConfirmDeadlineSeconds int64 `json:"confirm_deadline_seconds"`
}

func approveTask(c *gin.Context, co *task.Coordinator) {
	var body approveReq
	_ = c.ShouldBindJSON(&body)
	t, err := co.Approve(c.Request.Context(), c.Param("id"), actor(c),
		time.Duration(body.ConfirmDeadlineSeconds)*time.Second)
	if err != nil {
		respondTaskErr(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

type rejectReq struct {
	Reason string `json:"reason"`
}

func rejectTask(c *gin.Context, co *task.Coordinator) {
	var body rejectReq
	_ = c.ShouldBindJSON(&body)
	t, err := co.Reject(c.Request.Context(), c.Param("id"), actor(c), body.Reason)
	if err != nil {
		respondTaskErr(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

func confirmTask(c *gin.Context, co *task.Coordinator) {
	t, err := co.Confirm(c.Request.Context(), c.Param("id"), actor(c))
	if err != nil {
		respondTaskErr(c, err)
		return
	}
	c.JSON(http.StatusOK, t)
}

func respondTaskErr(c *gin.Context, err error) {
	if errors.Is(err, task.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
}
