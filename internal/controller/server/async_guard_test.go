package server

import (
	"testing"
	"time"
)

// TestApplyWaitTimeoutLowered:B3 降级——applyNow 同步等待上限不得高于 10s(8s 更佳)。
func TestApplyWaitTimeoutLowered(t *testing.T) {
	if applyWaitTimeout > 10*time.Second {
		t.Fatalf("applyWaitTimeout 应为 10s 内(降级),实际 %v", applyWaitTimeout)
	}
	if applyWaitTimeout <= 0 {
		t.Fatalf("applyWaitTimeout 必须为正,实际 %v", applyWaitTimeout)
	}
}

// TestNodeSyncLock_MutualExclusion:同 key 加锁期间 TryLock 返回 false,解锁后恢复。
func TestNodeSyncLock_MutualExclusion(t *testing.T) {
	l := &nodeSyncLockT{locks: make(map[string]bool)}
	if !l.TryLock("n1") {
		t.Fatal("首次加锁应成功")
	}
	if l.TryLock("n1") {
		t.Fatal("同 key 二次加锁应失败(防重入)")
	}
	if !l.TryLock("n2") {
		t.Fatal("不同 key 应互不影响")
	}
	l.Unlock("n1")
	if !l.TryLock("n1") {
		t.Fatal("解锁后应可重新加锁")
	}
	l.Unlock("n1")
	l.Unlock("n2")
}
