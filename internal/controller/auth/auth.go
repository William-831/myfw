package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	g := r.Group("/api/auth")
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
		token := h.generateToken(1, "admin")
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

func (h *Handler) generateToken(userID uint, username string) string {
	claims := TokenClaims{
		UserID:   userID,
		Username: username,
		Expires:  time.Now().Add(24 * time.Hour).Unix(),
	}
	buf, _ := json.Marshal(claims)
	return fmt.Sprintf("fake.%s", base64Encode(buf))
}

func (h *Handler) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		token := parts[1]
		if !strings.HasPrefix(token, "fake.") {
			c.Next()
			return
		}

		claimsData, err := base64Decode(strings.TrimPrefix(token, "fake."))
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

		c.Set("user", User{ID: claims.UserID, Username: claims.Username})
		c.Next()
	}
}

func base64Encode(data []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, ((len(data)+2)/3)*4)
	for i := 0; i < len(data); i += 3 {
		b0, b1, b2 := data[i], byte(0), byte(0)
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}
		result = append(result, table[b0>>2])
		result = append(result, table[((b0&3)<<4)|(b1>>4)])
		result = append(result, table[((b1&15)<<2)|(b2>>6)])
		result = append(result, table[b2&63])
	}
	if mod := len(data) % 3; mod != 0 {
		result[len(result)-1] = '='
		if mod == 1 {
			result[len(result)-2] = '='
		}
	}
	return string(result)
}

func base64Decode(data string) ([]byte, error) {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)*3)/4)
	var buffer uint32
	var bits uint
	for _, c := range data {
		if c == '=' {
			break
		}
		idx := strings.IndexRune(table, c)
		if idx == -1 {
			return nil, ErrInvalidToken
		}
		buffer = (buffer << 6) | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			result = append(result, byte(buffer>>bits))
		}
	}
	return result, nil
}

func ActorFromContext(ctx context.Context) string {
	if user, ok := ctx.Value("user").(User); ok {
		return user.Username
	}
	return "admin"
}