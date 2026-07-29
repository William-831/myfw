import { onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'

/**
 * ECharts 实例生命周期管理:自动 init、resize、dispose
 * @param {import('vue').Ref<HTMLElement|null>} elRef 图表容器 ref
 * @returns {{ setOption: (option: object) => void, resize: () => void }}
 */
export function useEcharts(elRef) {
  let chart = null

  const setOption = (option) => chart?.setOption(option, true)

  const resize = () => chart?.resize()

  onMounted(() => {
    if (elRef.value) chart = echarts.init(elRef.value)
    window.addEventListener('resize', resize)
  })

  onUnmounted(() => {
    window.removeEventListener('resize', resize)
    chart?.dispose()
    chart = null
  })

  return { setOption, resize }
}
