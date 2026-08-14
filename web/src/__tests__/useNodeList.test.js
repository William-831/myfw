import { describe, it, expect, vi, beforeEach } from 'vitest'
import { LABELS, TYPES, useStatusLabels } from '../composables/useStatusLabels'

vi.mock('@/api', () => ({
  getNodes: vi.fn(),
}))
const { getNodes } = await import('@/api')
const { useNodeList } = await import('../composables/useNodeList')

describe('useNodeList 节点列表复用 composable', () => {
  beforeEach(() => vi.clearAllMocks())

  it('loadNodes 加载节点列表并写入 nodes', async () => {
    getNodes.mockResolvedValue({ nodes: [{ id: 'n1', ip: '10.0.0.1', hostname: 'h1' }] })
    const { nodes, loadNodes } = useNodeList()
    await loadNodes()
    expect(nodes.value).toHaveLength(1)
    expect(nodes.value[0].ip).toBe('10.0.0.1')
  })

  it('nodeIP 优先 IP,其次 hostname,兜底 ID 前缀', async () => {
    getNodes.mockResolvedValue({ nodes: [
      { id: 'n1', ip: '10.0.0.1', hostname: 'h1' },
      { id: 'n2', hostname: 'h2' },
      { id: 'n3' },
    ] })
    const { loadNodes, nodeIP } = useNodeList()
    await loadNodes()
    expect(nodeIP('n1')).toBe('10.0.0.1')
    expect(nodeIP('n2')).toBe('h2')
    expect(nodeIP('n3')).toBe('n3')
    expect(nodeIP('missing')).toBe('missing')
  })

  it('onLoaded 钩子在加载完成后调用', async () => {
    getNodes.mockResolvedValue({ nodes: [] })
    const onLoaded = vi.fn()
    const { loadNodes } = useNodeList({ onLoaded })
    await loadNodes()
    expect(onLoaded).toHaveBeenCalled()
  })

  it('onError 钩子捕获加载异常(不抛出)', async () => {
    getNodes.mockRejectedValue(new Error('boom'))
    const onError = vi.fn()
    const { loadNodes } = useNodeList({ onError })
    await expect(loadNodes()).resolves.toBeUndefined()
    expect(onError).toHaveBeenCalled()
  })
})

describe('useStatusLabels 任务状态映射', () => {
  it('已收录状态返回中文标签', () => {
    expect(LABELS.pending_approval).toBe('待审批')
    expect(LABELS.confirm_wait).toBe('待确认')
    expect(LABELS.confirmed).toBe('已通过')
    expect(LABELS.rolled_back).toBe('已回滚')
    expect(LABELS.superseded).toBe('已接管')
    expect(LABELS.applying).toBe('处理中')
  })

  it('未收录状态回退原始状态', () => {
    const l = useStatusLabels('unknown_status')
    expect(l.label.value).toBe('unknown_status')
    expect(l.type.value).toBe('info')
  })

  it('已收录状态经 useStatusLabels 返回标签与类型', () => {
    expect(useStatusLabels('confirmed').label.value).toBe('已通过')
    expect(useStatusLabels('confirmed').type.value).toBe('success')
  })
})
