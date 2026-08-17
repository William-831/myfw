import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'

// mock api:任务列表 + 节点列表(useNodeList 内部调 getNodes)
const api = vi.hoisted(() => ({
  getTasks: vi.fn(),
  approveTask: vi.fn(),
  rejectTask: vi.fn(),
  confirmTask: vi.fn(),
  rollbackTask: vi.fn(),
  getNodes: vi.fn(),
}))
vi.mock('@/api', () => api)
vi.mock('element-plus', () => ({
  ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  ElMessageBox: { confirm: vi.fn(() => Promise.resolve()), prompt: vi.fn(() => Promise.resolve({ value: '' })) },
}))

import Approve from '../views/Approve.vue'

// 自定义 stub:el-table-column 不渲染 #default slot(el-table 的 scoped slot 需 row 上下文,
// 全量 'el-' stub 会直接把 slot 内容挂到无上下文处导致解构崩溃),其余组件浅渲染。
const stubs = {
  'el-card': { template: '<div><slot name="header" /><slot /></div>' },
  'el-table': { template: '<div><slot /></div>' },
  'el-table-column': { template: '<div />' },
  'el-tag': { template: '<span><slot /></span>' },
  'el-button': { template: '<button><slot /></button>' },
  'el-select': { template: '<div />' },
  'el-option': true,
  'el-dialog': { template: '<div />' },
  'el-descriptions': { template: '<div />' },
  'el-descriptions-item': { template: '<div />' },
}

const mountPage = async () => {
  const wrapper = mount(Approve, { global: { stubs } })
  // fakeTimers 下 flushPromises(setTimeout 被 fake)会挂起;原生 microtask 冲刷 onMounted 链
  for (let i = 0; i < 8; i++) await Promise.resolve()
  return wrapper
}

describe('Approve 5s 轮询(任务状态流转实时可见)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    api.getTasks.mockResolvedValue({ tasks: [] })
    api.getNodes.mockResolvedValue({ nodes: [] })
  })
  afterEach(() => vi.useRealTimers())

  it('挂载后拉取一次,之后每 5s 自动刷新任务列表', async () => {
    const wrapper = await mountPage()
    expect(api.getTasks).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(10000)
    expect(api.getTasks).toHaveBeenCalledTimes(3) // 初始 + 10s 内 2 次
    wrapper.unmount()
  })
})
