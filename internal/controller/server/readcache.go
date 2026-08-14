package server

import (
	"errors"
	"sync"
	"time"
)

// errTestCache 仅测试使用:GetOrCompute 计算返回错误时不应缓存。
var errTestCache = errors.New("test cache error")

// cacheItem 一条缓存记录:data 计算结果,exp 过期时间。
type cacheItem struct {
	data any
	exp  time.Time
}

// ReadCache 只读数据 TTL 内存缓存(非侵入:B2)。
// 用途:高频只读聚合接口(dashboard/stats、nodes/list)在 TTL 内复用,写操作后 DeletePrefix 失效。
// 特性:并发同 key 单飞(只计算一次,其余等待复用),错误结果不缓存(下次重试)。
// 线程安全:RWMutex 保护 map;单飞用 per-key mutex。
type ReadCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
	keys  map[string]*sync.Mutex // 单飞:同 key 并发只允许一个计算
}

// NewReadCache 创建空缓存。
func NewReadCache() *ReadCache {
	return &ReadCache{
		items: make(map[string]cacheItem),
		keys:  make(map[string]*sync.Mutex),
	}
}

// GetOrCompute 命中未过期缓存直接返回;否则执行 fn 计算并缓存(ttl 后过期)。
// fn 返回错误时不缓存,由调用方决定降级;并发同 key 只执行一次 fn。
func (rc *ReadCache) GetOrCompute(key string, ttl time.Duration, fn func() (any, error)) (any, error) {
	rc.mu.RLock()
	item, ok := rc.items[key]
	rc.mu.RUnlock()
	if ok && time.Now().Before(item.exp) {
		return item.data, nil
	}

	// 单飞:拿到该 key 的锁,避免缓存失效瞬间 N 个并发重复计算
	rc.mu.Lock()
	mu := rc.keys[key]
	if mu == nil {
		mu = &sync.Mutex{}
		rc.keys[key] = mu
	}
	rc.mu.Unlock()

	mu.Lock()
	defer mu.Unlock()

	// 双检:等待锁期间可能已被其他 goroutine 填充
	rc.mu.RLock()
	item, ok = rc.items[key]
	rc.mu.RUnlock()
	if ok && time.Now().Before(item.exp) {
		return item.data, nil
	}

	data, err := fn()
	if err != nil {
		return nil, err // 错误不缓存
	}
	rc.mu.Lock()
	rc.items[key] = cacheItem{data: data, exp: time.Now().Add(ttl)}
	rc.mu.Unlock()
	return data, nil
}

// DeletePrefix 删除指定前缀的所有缓存(写操作后整体刷新,保证一致性)。
func (rc *ReadCache) DeletePrefix(prefix string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for k := range rc.items {
		if len(prefix) <= len(k) && k[:len(prefix)] == prefix {
			delete(rc.items, k)
		}
	}
}
