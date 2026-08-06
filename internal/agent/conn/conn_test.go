package conn

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestShouldSelfDestruct 验证：仅 Controller 明确拒绝（证书吊销/未知、节点归档/删除）
// 时触发自毁；网络错误与取消照常重试。
func TestShouldSelfDestruct(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil 不自毁", nil, false},
		{"证书吊销自毁", status.Error(codes.Unauthenticated, "certificate revoked"), true},
		{"未知证书自毁", status.Error(codes.Unauthenticated, "unknown certificate"), true},
		{"节点归档自毁", status.Error(codes.PermissionDenied, "node archived"), true},
		{"网络不可达重试", status.Error(codes.Unavailable, "connection refused"), false},
		{"内部错误重试", status.Error(codes.Internal, "boom"), false},
		{"上下文取消重试", context.Canceled, false},
		{"包装的 Unauthenticated 自毁", fmt.Errorf("dial: %w", status.Error(codes.Unauthenticated, "revoked")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSelfDestruct(tt.err); got != tt.want {
				t.Errorf("ShouldSelfDestruct() = %v, want %v", got, tt.want)
			}
		})
	}
}
