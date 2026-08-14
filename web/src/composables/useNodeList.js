import { ref } from 'vue'
import { getNodes } from '@/api'

// 节点列表复用 composable:集中加载 + 缓存反查 + IP 显示。
// 收敛 Nodes/Approve/Audit/ExpertMode/NodePolicies/ConfirmGuard 各页重复的
// loadNodes/nodes/nodeIP 样板;节点字段变更只改此处。
// opts.onLoaded:加载完成后的钩子(如 Nodes 页继续加载保护期任务)。
export function useNodeList(opts = {}) {
  const nodes = ref([])

  const loadNodes = async () => {
    try {
      const data = await getNodes()
      nodes.value = data.nodes || []
      if (opts.onLoaded) opts.onLoaded()
      return nodes.value
    } catch (e) {
      if (opts.onError) opts.onError(e)
      else throw e
    }
  }

  // 节点 ID -> 展示名(优先 IP,其次 hostname,兜底 ID 前缀)
  const nodeIP = (id) => {
    const n = nodes.value.find((x) => x.id === id)
    return n ? (n.ip || n.hostname || id.slice(0, 12)) : id.slice(0, 12)
  }

  return { nodes, loadNodes, nodeIP }
}
