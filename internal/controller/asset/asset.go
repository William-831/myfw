// Package asset exposes the Controller's REST endpoints for node lifecycle:
// creating bootstrap tokens, listing nodes (in particular PENDING ones), and
// approving/rejecting them. See docs/design.md § 13.3.
//
// M3: authentication is not yet wired. Every route is open; user auth lands
// with the auth module in a later milestone. A well-known "admin" actor is
// used for audit until then.
package asset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// AuditSink matches internal/controller/audit.Sink without importing it, so we
// keep asset -> audit as a one-way runtime dependency.
type AuditSink interface {
	Write(ctx context.Context, e model.AuditLog) error
}

// Handler owns the DB and configuration needed by the asset routes.
type Handler struct {
	DB         *gorm.DB
	Audit      AuditSink
	TokenTTL   time.Duration
	adminActor string
}

// New builds a Handler using default admin actor "admin".
func New(db *gorm.DB, audit AuditSink, tokenTTL time.Duration) *Handler {
	return &Handler{DB: db, Audit: audit, TokenTTL: tokenTTL, adminActor: "admin"}
}

// Register mounts the /api/v1 routes onto r.
func (h *Handler) Register(r gin.IRouter) {
	g := r.Group("/api/v1")
	g.POST("/nodes/bootstrap", h.createBootstrapToken)
	g.GET("/nodes", h.listNodes)
	g.POST("/nodes/:id/approve", h.approveNode)
	g.POST("/nodes/:id/reject", h.rejectNode)
}

// ---- routes ----------------------------------------------------------------

type createTokenReq struct {
	Note string `json:"note"`
}

type createTokenResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) createBootstrapToken(c *gin.Context) {
	var req createTokenReq
	_ = c.ShouldBindJSON(&req) // note is optional; body may be empty

	raw, err := randToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tok := model.BootstrapToken{
		Token:     raw,
		Note:      req.Note,
		ExpiresAt: time.Now().Add(h.TokenTTL),
	}
	if err := h.DB.WithContext(c.Request.Context()).Create(&tok).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = h.audit(c, "bootstrap.create", "", "", map[string]any{
		"note":       req.Note,
		"expires_at": tok.ExpiresAt,
	})
	c.JSON(http.StatusCreated, createTokenResp{Token: raw, ExpiresAt: tok.ExpiresAt})
}

func (h *Handler) listNodes(c *gin.Context) {
	status := c.Query("status") // optional filter: PENDING / ACTIVE / ...
	var nodes []model.Node
	q := h.DB.WithContext(c.Request.Context()).Order("created_at DESC")
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if err := q.Find(&nodes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes})
}

func (h *Handler) approveNode(c *gin.Context) {
	h.transitionNode(c, model.NodeStatusPending, model.NodeStatusActive, "node.approve")
}

func (h *Handler) rejectNode(c *gin.Context) {
	h.transitionNode(c, model.NodeStatusPending, model.NodeStatusArchived, "node.reject")
}

// transitionNode enforces the "from -> to" state change atomically. Returns
// 404 if not found, 409 if the node isn't in the expected source state.
func (h *Handler) transitionNode(c *gin.Context, from, to model.NodeStatus, action string) {
	id := c.Param("id")
	ctx := c.Request.Context()

	err := h.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var node model.Node
		if err := tx.Where("id = ?", id).First(&node).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
			}
			return err
		}
		if node.Status != from {
			c.JSON(http.StatusConflict, gin.H{"error": "node not in " + string(from) + " state", "actual": node.Status})
			return errors.New("wrong state")
		}
		if err := tx.Model(&node).Update("status", to).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return err
		}
		return nil
	})
	if err != nil {
		return
	}

	_ = h.audit(c, action, id, "", map[string]any{"from": from, "to": to})
	c.JSON(http.StatusOK, gin.H{"id": id, "status": to})
}

// ---- helpers ---------------------------------------------------------------

func (h *Handler) audit(c *gin.Context, action, nodeID, taskID string, detail map[string]any) error {
	if h.Audit == nil {
		return nil
	}
	buf, _ := json.Marshal(detail)
	return h.Audit.Write(c.Request.Context(), model.AuditLog{
		Actor:  h.adminActor,
		Action: action,
		NodeID: nodeID,
		TaskID: taskID,
		Detail: string(buf),
	})
}

func randToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
