import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createGetCache } from '../api/cache'

describe('createGetCache 只读 GET 缓存', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('TTL 内同 key 第二次调用不触发 fetcher(命中缓存)', async () => {
    const fetcher = vi.fn().mockResolvedValue('data-v1')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    expect(await cache.get('k1')).toBe('data-v1')
    expect(await cache.get('k1')).toBe('data-v1')
    expect(fetcher).toHaveBeenCalledTimes(1) // 第二次命中缓存
  })

  it('TTL 过期后重新触发 fetcher', async () => {
    const fetcher = vi.fn().mockResolvedValue('data-v1')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    await cache.get('k1')
    await vi.advanceTimersByTimeAsync(5001)
    fetcher.mockResolvedValue('data-v2')
    expect(await cache.get('k1')).toBe('data-v2')
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('不同 key 缓存相互独立', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce('a')
      .mockResolvedValueOnce('b')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    expect(await cache.get('k1')).toBe('a')
    expect(await cache.get('k2')).toBe('b')
    expect(await cache.get('k1')).toBe('a')
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('invalidate 指定 key 后强制重新拉取', async () => {
    const fetcher = vi.fn().mockResolvedValue('old')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    await cache.get('k1')
    fetcher.mockResolvedValue('new')
    cache.invalidate('k1')
    expect(await cache.get('k1')).toBe('new')
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('invalidatePrefix 按前缀批量失效(写操作后整体刷新)', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce('a1')
      .mockResolvedValueOnce('a2')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    await cache.get('nodes:list')
    await cache.get('nodes:other')
    cache.invalidatePrefix('nodes')
    fetcher.mockResolvedValue('new')
    expect(await cache.get('nodes:list')).toBe('new')
    expect(await cache.get('nodes:other')).toBe('new')
  })

  it('fetcher 抛错时返回 reject 且不缓存错误', async () => {
    const fetcher = vi.fn()
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce('ok')
    const cache = createGetCache({ fetcher, ttl: 5000 })
    await expect(cache.get('k1')).rejects.toThrow('network')
    expect(await cache.get('k1')).toBe('ok')
    expect(fetcher).toHaveBeenCalledTimes(2) // 错误未缓存,重试成功
  })
})
