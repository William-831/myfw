import { describe, it, expect, vi, beforeEach } from 'vitest'

// mock axios:api/index.js 顶层 axios.create() 返回带 interceptors 的实例,
// 避免真实发请求。测试只关心 mockGet 调用次数(缓存命中/失效),不关心返回值。
const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }))
vi.mock('axios', () => ({
  default: {
    create: () => ({
      get: mockGet,
      post: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    }),
  },
}))

import { getNodes, getAddressGroups, invalidateAfterWrite, readCaches } from '../api'

describe('invalidateAfterWrite 写后缓存失效(修复前缀 bug)', () => {
  beforeEach(() => {
    mockGet.mockReset()
    mockGet.mockResolvedValue({ data: { nodes: [], groups: [] } })
    // 用例间隔离:清空两个缓存(不依赖被测的 invalidateAfterWrite)
    readCaches.nodes.clear()
    readCaches.dicts.clear()
  })

  it('nodes 写后失效:getNodes 填缓存后,invalidateAfterWrite(nodes) 清缓存,下次重新拉', async () => {
    await getNodes()
    await getNodes()
    expect(mockGet).toHaveBeenCalledTimes(1) // TTL 内命中缓存
    invalidateAfterWrite('nodes')
    await getNodes()
    expect(mockGet).toHaveBeenCalledTimes(2) // 失效后重新拉取
  })

  it('dicts 写后失效:getAddressGroups 填缓存后,invalidateAfterWrite() 清缓存,下次重新拉', async () => {
    await getAddressGroups()
    await getAddressGroups()
    expect(mockGet).toHaveBeenCalledTimes(1)
    invalidateAfterWrite() // 无参走 dicts 分支
    await getAddressGroups()
    expect(mockGet).toHaveBeenCalledTimes(2)
  })

  it('nodes 与 dicts 缓存独立失效:nodes 失效不影响 dicts 命中', async () => {
    await getNodes()
    await getAddressGroups()
    expect(mockGet).toHaveBeenCalledTimes(2) // 各拉一次
    invalidateAfterWrite('nodes')
    await getAddressGroups()
    expect(mockGet).toHaveBeenCalledTimes(2) // dicts 仍命中,不重拉
    await getNodes()
    expect(mockGet).toHaveBeenCalledTimes(3) // nodes 失效后重拉
  })
})
