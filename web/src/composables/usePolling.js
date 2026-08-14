import { onMounted, onUnmounted, watch } from 'vue'

// 统一轮询 composable:挂载自动启动、卸载自动停止、防重入节流。
// enabled:可选响应式条件回调,返回 false 时暂停轮询(如无在途任务时空转保护)。
// 防重入:上一轮 fn 未完成时跳过本次触发,避免慢响应期请求无限堆积。
// 用法:const { start, stop } = usePolling(loadTasks, 5000)              // 无条件轮询
//       usePolling(refreshInflight, 5000, () => inflightTasks.length)   // 条件轮询
export function usePolling(fn, interval = 5000, enabled) {
  const shouldRun = typeof enabled === 'function' ? enabled : () => true
  let timer = null
  let running = false

  const tick = async () => {
    if (running) return // 防重入:上一轮未完成则跳过本次
    running = true
    try {
      await fn()
    } catch {
      // 异常隔离:轮询回调失败不中断后续周期,也不产生 unhandled rejection
    } finally {
      running = false
    }
  }

  const start = () => {
    if (timer) return
    if (!shouldRun()) return // 条件不满足时保持停止,避免空转请求
    timer = setInterval(tick, interval)
  }

  const stop = () => {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
    running = false
  }

  // 条件启停:条件(响应式依赖)满足即启动,不满足即停止,初始立即求值
  watch(shouldRun, (v) => (v ? start() : stop()), { immediate: true })
  onMounted(start)
  onUnmounted(stop)
  return { start, stop }
}
