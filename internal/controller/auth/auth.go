package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidToken = errors.New("invalid token")
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

	if req.Username == "admin" && req.Password == "admin123" {
		token := generateToken(1, "admin")
		c.JSON(http.StatusOK, loginResp{Token: token, Username: "admin"})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
}

func (h *Handler) me(c *gin.Context) {
	user, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	c.JSON(http.StatusOK, user)
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
