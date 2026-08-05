<template>
  <section class="panel">
    <header class="panel__head">节点状态分布</header>
    <div class="status">
      <div ref="chartRef" class="status__chart"></div>
      <ul class="status__legend">
        <li v-for="item in items" :key="item.name" class="legend-item">
          <span class="legend-item__dot" :style="{ background: item.color }"></span>
          <span class="legend-item__name">{{ item.name }}</span>
          <span class="legend-item__value">{{ item.value }}</span>
          <span class="legend-item__pct">{{ item.pct }}%</span>
        </li>
      </ul>
    </div>
  </section>
</template>

<script setup>
import { computed, ref, watch, onMounted } from 'vue'
import { useEcharts } from '@/composables/useEcharts'

/**
 * 节点状态分布:精致环形饼图 + 中心总数 + 图例(色点/名称/数值/占比)
 */
const props = defineProps({
  total: { type: Number, default: 0 },
  active: { type: Number, default: 0 },
  pending: { type: Number, default: 0 },
  abnormal: { type: Number, default: 0 }
})

const chartRef = ref(null)
const { setOption } = useEcharts(chartRef)

// 离线数 = 总数 - 在线 - 待审核 - 异常
const offline = computed(() =>
  Math.max(0, props.total - props.active - props.pending - props.abnormal)
)

// 图例数据:名称 / 数值 / 占比
const items = computed(() => {
  const base = props.total || 1
  const mk = (name, value, color) => ({
    name, value, color, pct: Math.round((value / base) * 100)
  })
  return [
    mk('在线', props.active, '#34d399'),
    mk('离线', offline.value, '#64748b'),
    mk('待审核', props.pending, '#fbbf24'),
    mk('异常', props.abnormal, '#fb7185')
  ]
})

// 渲染环形图:细环 + 圆角 + 段间留白 + 中心数字
const render = () => {
  setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} 个 ({d}%)' },
    graphic: [
      { type: 'text', left: 'center', top: '40%', style: { text: `${props.total}`, fontSize: 30, fontWeight: 600, fill: '#f1f5f9', textAlign: 'center' } },
      { type: 'text', left: 'center', top: '58%', style: { text: '节点总数', fontSize: 12, fill: '#cbd5e1', textAlign: 'center' } }
    ],
    series: [{
      type: 'pie',
      radius: ['58%', '78%'],
      center: ['50%', '50%'],
      avoidLabelOverlap: false,
      cursor: 'pointer',
      itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 3 },
      label: { show: false },
      labelLine: { show: false },
      emphasis: { scaleSize: 6 },
      data: items.value.map((it) => ({ value: it.value, name: it.name, itemStyle: { color: it.color } }))
    }]
  })
}

onMounted(render)
watch(() => [props.total, props.active, props.pending, props.abnormal], render)
</script>

<style scoped>
.panel {
  display: flex;
  flex-direction: column;
  min-height: 0;
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius);
  overflow: hidden;
}

.panel__head {
  flex: 0 0 auto;
  padding: 16px 20px;
  font-size: 15px;
  font-weight: 600;
  color: var(--c-text-1);
  border-bottom: 1px solid var(--c-border-soft);
}

.status {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 18px;
  padding: 16px 20px;
}

.status__chart {
  width: 100%;
  height: 200px;
}

.status__legend {
  width: 100%;
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 16px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}

.legend-item__dot {
  flex: 0 0 8px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.legend-item__name {
  color: var(--c-text-2);
}

.legend-item__value {
  margin-left: auto;
  font-weight: 600;
  color: var(--c-text-1);
  font-variant-numeric: tabular-nums;
}

.legend-item__pct {
  width: 38px;
  text-align: right;
  color: var(--c-text-3);
  font-variant-numeric: tabular-nums;
}
</style>
