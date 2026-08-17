// 只读 GET 内存 TTL 缓存:同 key 在 TTL 内只发一次请求,降重复拉取。
// 写操作后调用 invalidate/invalidatePrefix 主动失效,保证一致性。
// 注意:仅用于无参只读 GET,带 params 的查询(如任务/审计筛选)不适用。
// fetcher 可在创建时注入(纯逻辑测试),也可在 get() 调用时按 key 传入(api 层多 URL 复用)。
export function createGetCache({ fetcher, ttl = 5000 } = {}) {
  const store = new Map()

  const get = async (key, fn) => {
    const hit = store.get(key)
    if (hit && Date.now() < hit.exp) return hit.data
    const load = fn || fetcher
    if (typeof load !== 'function') throw new Error(`cache.get("${key}") 缺少 fetcher`)
    const data = await load(key) // 抛错不缓存,由调用方捕获
    store.set(key, { data, exp: Date.now() + ttl })
    return data
  }

  const invalidate = (key) => { store.delete(key) }
  const invalidatePrefix = (prefix) => {
    for (const k of store.keys()) {
      if (k.startsWith(prefix)) store.delete(k)
    }
  }
  // 全清(写操作后整体刷新):字典缓存多 key 交叉引用,按前缀逐条匹配易漏,clear 兜底。
  const clear = () => { store.clear() }

  return { get, invalidate, invalidatePrefix, clear }
}
