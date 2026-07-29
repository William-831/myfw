package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidToken = errors.New("invalid token")
)

// 默认管理员凭据:库中无 User 记录时回退使用,首次修改密码后写入库
const (
	defaultUsername = "admin"
	defaultPassword = "admin123"
)

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type TokenClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Expires  int64  `json:"exp"`
}

type Handler struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) Register(r gin.IRouter) {
	r.Use(h.middleware())
	g := r.Group("/api/v1/auth")
	g.POST("/login", h.login)
	g.GET("/me", h.me)
	g.POST("/change-password", h.changePassword)
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

func (h *Handler) login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !h.verifyCredentials(req.Username, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	token := generateToken(1, req.Username)
	c.JSON(http.StatusOK, loginResp{Token: token, Username: req.Username})
}

func (h *Handler) me(c *gin.Context) {
	user, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	c.JSON(http.StatusOK, user)
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// changePassword 校验旧密码后写入新密码哈希(库中无记录则创建)
func (h *Handler) changePassword(c *gin.Context) {
	u, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	user := u.(User)

	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(req.NewPassword) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码至少 6 位"})
		return
	}
	if !h.verifyCredentials(user.Username, req.OldPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "旧密码错误"})
		return
	}

	salt := newSalt()
	hash := hashPassword(salt, req.NewPassword)
	var row model.User
	err := h.db.Where("username = ?", user.Username).First(&row).Error
	if err != nil {
		// 库中无记录(默认凭据首次改密),创建
		row = model.User{Username: user.Username, Salt: salt, PasswordHash: hash}
		if err := h.db.Create(&row).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存密码失败"})
			return
		}
	} else {
		row.Salt = salt
		row.PasswordHash = hash
		if err := h.db.Save(&row).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存密码失败"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
}

// verifyCredentials 校验用户名密码:库中有记录则校验哈希,无记录回退默认 admin/admin123
func (h *Handler) verifyCredentials(username, password string) bool {
	var row model.User
	err := h.db.Where("username = ?", username).First(&row).Error
	if err == nil {
		return row.PasswordHash == hashPassword(row.Salt, password)
	}
	return username == defaultUsername && password == defaultPassword
}

// hashPassword = sha256(salt + password) 的十六进制
func hashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(sum[:])
}

// newSalt 生成 16 字节随机盐
func newSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fixed-salt-fallback"
	}
	return hex.EncodeToString(b)
}

func generateToken(userID uint, username string) string {
	claims := TokenClaims{
		UserID:   userID,
		Username: username,
		Expires:  time.Now().Add(24 * time.Hour).Unix(),
	}
	buf, _ := json.Marshal(claims)
	return "fake." + base64.StdEncoding.EncodeToString(buf)
}

func (h *Handler) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		token := parts[1]
		if !strings.HasPrefix(token, "fake.") {
			c.Next()
			return
		}

		claimsData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "fake."))
		if err != nil {
			c.Next()
			return
		}

		var claims TokenClaims
		if err := json.Unmarshal(claimsData, &claims); err != nil {
			c.Next()
			return
		}

		if claims.Expires < time.Now().Unix() {
			c.Next()
			return
		}

		user := User{ID: claims.UserID, Username: claims.Username}
		c.Set("user", user)
		// 同时存入标准 context，使 ActorFromContext 可读取
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), userContextKey{}, user))
		c.Next()
	}
}

func ActorFromContext(ctx context.Context) string {
	if user, ok := ctx.Value(userContextKey{}).(User); ok {
		return user.Username
	}
	return "admin"
}

// userContextKey 是 context.Value 中用户信息的键类型
type userContextKey struct{}
