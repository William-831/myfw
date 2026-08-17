import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'

// mock api:仪表盘聚合统计 + 配置漂移 + 最近审计
const api = vi.hoisted(() => ({
  getDashboardStats: vi.fn(),
  getConfigDrift: vi.fn(),
  getAuditLogs: vi.fn(),
}))
vi.mock('@/api', () => api)

import Dashboard from '../views/Dashboard.vue'

const calls = () => [api.getDashboardStats.mock.calls.length, api.getConfigDrift.mock.calls.length, api.getAuditLogs.mock.calls.length].join('/')

describe('Dashboard 10s 轮询(免手动刷新页面)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    api.getDashboardStats.mockResolvedValue({ node_count: 1, active_node_count: 1, pending_node_count: 0, abnormal_node_count: 0, policy_count: 0, active_policy_count: 0, pending_task_count: 0 })
    api.getConfigDrift.mockResolvedValue({ total: 0, nodes: [] })
    api.getAuditLogs.mockResolvedValue({ data: [], total: 0 })
  })
  afterEach(() => vi.useRealTimers())

  it('挂载后拉取一次,之后每 10s 自动刷新统计/漂移/审计', async () => {
    const wrapper = mount(Dashboard, {
      global: { stubs: { StatCard: true, StatusPanel: true, AuditFeed: true } },
    })
    expect(api.getDashboardStats).toHaveBeenCalledTimes(1) // mount 同步调用
    console.error('T0 calls', calls())
    await vi.advanceTimersByTimeAsync(10000)
    console.error('T1 calls', calls())
    expect(api.getDashboardStats).toHaveBeenCalledTimes(2)
    expect(api.getConfigDrift).toHaveBeenCalledTimes(2)
    expect(api.getAuditLogs).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })
})
