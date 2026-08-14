package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReadCache_HitWithinTTL:TTL 内重复 Get 只执行一次计算。
func TestReadCache_HitWithinTTL(t *testing.T) {
	rc := NewReadCache()
	var calls atomic.Int64
	rc.GetOrCompute("k", 5*time.Second, func() (any, error) {
		calls.Add(1)
		return "v1", nil
	})
	rc.GetOrCompute("k", 5*time.Second, func() (any, error) {
		calls.Add(1)
		return "v2", nil
	})
	if calls.Load() != 1 {
		t.Fatalf("TTL 内应只计算 1 次,实际 %d", calls.Load())
	}
}

// TestReadCache_ExpiryRecomputes:TTL 过期后重新计算。
func TestReadCache_ExpiryRecomputes(t *testing.T) {
	rc := NewReadCache()
	var calls atomic.Int64
	fn := func() (any, error) { calls.Add(1); return "v", nil }
	rc.GetOrCompute("k", 10*time.Millisecond, fn)
	time.Sleep(30 * time.Millisecond)
	rc.GetOrCompute("k", 10*time.Millisecond, fn)
	if calls.Load() != 2 {
		t.Fatalf("过期后应重新计算,实际 %d 次", calls.Load())
	}
}

// TestReadCache_DeletePrefix:前缀失效后重新计算(写操作后刷新)。
func TestReadCache_DeletePrefix(t *testing.T) {
	rc := NewReadCache()
	var calls atomic.Int64
	fn := func() (any, error) { calls.Add(1); return "v", nil }
	rc.GetOrCompute("nodes:list", time.Minute, fn)
	rc.DeletePrefix("nodes")
	rc.GetOrCompute("nodes:list", time.Minute, fn)
	if calls.Load() != 2 {
		t.Fatalf("失效后应重新计算,实际 %d 次", calls.Load())
	}
}

// TestReadCache_ConcurrentSingleFlight:并发同 key 只计算一次(单飞)。
func TestReadCache_ConcurrentSingleFlight(t *testing.T) {
	rc := NewReadCache()
	var calls atomic.Int64
	fn := func() (any, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // 模拟耗时计算
		return "v", nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rc.GetOrCompute("k", time.Minute, fn) }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("并发应单飞只计算 1 次,实际 %d", calls.Load())
	}
}

// TestReadCache_ErrorNotCached:计算返回错误时不缓存,下次重试。
func TestReadCache_ErrorNotCached(t *testing.T) {
	rc := NewReadCache()
	var calls atomic.Int64
	_, err := rc.GetOrCompute("k", time.Minute, func() (any, error) {
		calls.Add(1)
		if calls.Load() == 1 {
			return nil, errTestCache
		}
		return "ok", nil
	})
	if err == nil {
		t.Fatal("首次应返回错误")
	}
	v, err := rc.GetOrCompute("k", time.Minute, func() (any, error) {
		calls.Add(1)
		return "ok", nil
	})
	if err != nil || v != "ok" {
		t.Fatalf("错误不缓存后应重试成功,got v=%v err=%v", v, err)
	}
}
