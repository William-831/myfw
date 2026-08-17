import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

// ---- mock 依赖 ----
const api = vi.hoisted(() => ({
  updateInstance: vi.fn(),
  dispatchNode: vi.fn(),
  getNodes: vi.fn().mockResolvedValue({ nodes: [{ id: 'n1', ip: '10.0.0.1' }] }),
  getNodeInstances: vi.fn().mockResolvedValue({ instances: [] }),
  getTasks: vi.fn().mockResolvedValue({ tasks: [] }),
  getTask: vi.fn().mockResolvedValue({}),
  getTemplates: vi.fn().mockResolvedValue({ templates: [] }),
  getCustomChains: vi.fn().mockResolvedValue({ chains: [] }),
  getAddressGroups: vi.fn().mockResolvedValue({ groups: [] }),
  getMarks: vi.fn().mockResolvedValue({ marks: [] }),
  getNodeRuleHits: vi.fn().mockResolvedValue({ hits: [] }),
}))

vi.mock('@/api', () => api)
// guard store 用 hoisted 共享实例,便于断言 toggleEnabled 后待确认区联动刷新
const guardStore = vi.hoisted(() => ({ refreshTick: 0, open: vi.fn(), close: vi.fn(), refresh: vi.fn() }))
vi.mock('@/stores/guard', () => ({
  useGuardStore: () => guardStore,
}))
vi.mock('@/composables/useCommandPreview', () => ({
  buildCommandPreview: () => 'preview',
}))

const push = vi.fn()
vi.mock('vue-router', () => ({
  useRoute: () => ({ query: { node: 'n1' } }),
  useRouter: () => ({ push }),
}))
vi.mock('element-plus', () => ({
  ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  ElMessageBox: { confirm: vi.fn(() => Promise.resolve()), alert: vi.fn() },
}))

import NodePolicies from '../views/NodePolicies.vue'

// 挂载辅助:stub element-plus 子组件,避免真实渲染;route.query.node=n1 触发 selectNode
const mountPage = async () => {
  const wrapper = mount(NodePolicies, {
    global: { stubs: { 'el-switch': true, 'el-': true, ExpertMode: true } },
  })
  await flushPromises() // 等待 onMounted 选中节点
  return wrapper
}

describe('NodePolicies toggleEnabled 乐观更新', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    guardStore.refresh.mockClear()
    api.getNodes.mockResolvedValue({ nodes: [{ id: 'n1', ip: '10.0.0.1' }] })
    api.getNodeInstances.mockResolvedValue({ instances: [] })
    api.getTasks.mockResolvedValue({ tasks: [] })
  })

  it('乐观翻转:调用后 enabled 立即变为目标值,不等接口返回', async () => {
    let resolveUpdate
    api.updateInstance.mockReturnValue(new Promise((r) => { resolveUpdate = r }))
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't1' }] })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: false }
    const p = wrapper.vm.toggleEnabled(inst, true)
    // 接口未 resolve,乐观值已生效
    expect(inst.enabled).toBe(true)
    resolveUpdate({})
    await p
    wrapper.unmount()
  })

  it('成功后下发并提示', async () => {
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't1' }] })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: false }
    await wrapper.vm.toggleEnabled(inst, true)
    expect(api.updateInstance).toHaveBeenCalledWith(1, expect.objectContaining({ enabled: true }))
    expect(api.dispatchNode).toHaveBeenCalledWith('n1', { auto_approve: true })
    expect(inst.enabled).toBe(true)
    wrapper.unmount()
  })

  it('失败回滚:接口报错时 enabled 恢复原值', async () => {
    api.updateInstance.mockRejectedValue({ response: { data: { error: '节点忙' } } })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: false }
    await wrapper.vm.toggleEnabled(inst, true)
    expect(inst.enabled).toBe(false) // 回滚
    expect(api.dispatchNode).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('dispatch 失败同样回滚', async () => {
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockRejectedValue({ response: { data: { error: '409 busy' } } })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: true, applied: true } // 禁用已下发实例才走 dispatch
    await wrapper.vm.toggleEnabled(inst, false)
    expect(inst.enabled).toBe(true) // 回滚
    wrapper.unmount()
  })

  it('禁用未下发实例(applied=false):只改状态不 dispatch,不产生保护期任务', async () => {
    // 节点上无该实例规则,禁用无规则可移除;原实现无条件 dispatchNode,
    // 后端 disabling 查询(applied=true)匹配不到 -> change_type 落 default 'dispatch',
    // 待确认区误显示"节点策略下发待确认"(应不产生任务)
    api.updateInstance.mockResolvedValue({})
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: true, applied: false }
    await wrapper.vm.toggleEnabled(inst, false)
    expect(api.updateInstance).toHaveBeenCalledWith(1, expect.objectContaining({ enabled: false }))
    expect(api.dispatchNode).not.toHaveBeenCalled()
    expect(guardStore.refresh).not.toHaveBeenCalled()
    expect(inst.enabled).toBe(false)
    wrapper.unmount()
  })

  it('操作成功后联动保护期待确认区立即刷新(guard.refresh)', async () => {
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't1' }] })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: false }
    await wrapper.vm.toggleEnabled(inst, true)
    expect(guardStore.refresh).toHaveBeenCalled()
    wrapper.unmount()
  })

  it('启动操作后条目显示"下发待确认"(意图化标签,对齐保护期面板语义)', async () => {
    api.getNodeInstances.mockResolvedValue({ instances: [{ id: 1, name: 'allow-ssh', enabled: false, applied: true, group_id: 1 }] })
    // 节点已有 confirm_wait 任务 -> nodeInGuard=true,保护期接管中
    api.getTasks.mockResolvedValue({ tasks: [{ id: 't1', node_id: 'n1', status: 'confirm_wait' }] })
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't2' }] })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: false }
    await wrapper.vm.toggleEnabled(inst, true) // 启动 -> 意图 dispatch
    await flushPromises()
    expect(wrapper.text()).toContain('下发待确认')
    expect(wrapper.text()).not.toContain('移除待确认')
    wrapper.unmount()
  })

  it('禁用操作后条目显示"移除待确认"(意图化,不依赖 enabled 可变值)', async () => {
    api.getNodeInstances.mockResolvedValue({ instances: [{ id: 1, name: 'allow-ssh', enabled: true, applied: true, group_id: 1 }] })
    api.getTasks.mockResolvedValue({ tasks: [{ id: 't1', node_id: 'n1', status: 'confirm_wait' }] })
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't2' }] })
    const wrapper = await mountPage()
    const inst = { id: 1, enabled: true, applied: true } // 已下发实例禁用走 dispatch
    await wrapper.vm.toggleEnabled(inst, false) // 禁用 -> 意图 remove
    await flushPromises()
    expect(wrapper.text()).toContain('移除待确认')
    expect(wrapper.text()).not.toContain('下发待确认')
    wrapper.unmount()
  })

  // dispatch 异步:任务从 applying 到 confirm_wait 有延迟。原实现立即 guard.refresh,
  // ConfirmGuard 查 confirm_wait 为空 -> 待确认区没状态,需刷新页面才见(BUG)。
  // 修复:后台 pollTaskDone 等 confirm_wait 后再联动刷新。
  it('dispatch 后台等任务到 confirm_wait 再联动待确认区刷新', async () => {
    vi.useFakeTimers()
    api.updateInstance.mockResolvedValue({})
    api.dispatchNode.mockResolvedValue({ tasks: [{ id: 't9' }] })
    api.getTask.mockResolvedValue({ id: 't9', status: 'confirm_wait' })
    // fakeTimers 下 flushPromises(基于 setTimeout)挂起,改用原生 microtask 冲刷挂载链
    const wrapper = mount(NodePolicies, { global: { stubs: { 'el-switch': true, 'el-': true, ExpertMode: true } } })
    for (let i = 0; i < 8; i++) await Promise.resolve()
    guardStore.refresh.mockClear()
    await wrapper.vm.toggleEnabled({ id: 1, enabled: false, applied: true }, true)
    expect(guardStore.refresh).toHaveBeenCalledTimes(1) // 立即一次(此时任务可能还在 applying)
    await vi.advanceTimersByTimeAsync(1100) // pollTaskDone 1s 轮询命中 confirm_wait
    expect(api.getTask).toHaveBeenCalledWith('t9')
    expect(guardStore.refresh).toHaveBeenCalledTimes(2) // confirm_wait 后再联动
    vi.useRealTimers()
    wrapper.unmount()
  })
})
