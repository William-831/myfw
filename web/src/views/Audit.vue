<template>
  <div class="audit-dashboard">
    <!-- 顶部统计:微环图 + 进度条 + 数字卡 -->
    <div class="stats-row">
      <div class="ring-card">
        <svg viewBox="0 0 120 120" class="ring-svg">
          <circle cx="60" cy="60" r="48" fill="none" stroke="var(--c-border)" stroke-width="8"/>
          <circle cx="60" cy="60" r="48" fill="none" :stroke="healthColor" stroke-width="8"
            :stroke-dasharray="302" :stroke-dashoffset="302 * (1 - healthRate)" transform="rotate(-90 60 60)" stroke-linecap="round"/>
          <text x="60" y="52" text-anchor="middle" fill="var(--c-text-1)" font-size="22" font-weight="700">{{ Math.round(healthRate * 100) }}%</text>
          <text x="60" y="72" text-anchor="middle" fill="var(--c-text-2)" font-size="11">健康率</text>
        </svg>
        <div class="ring-sub">已确认 {{ dash.summary.confirmed || 0 }}</div>
      </div>
      <div class="progress-card">
        <div class="pc-label">回滚消耗</div>
        <div class="pc-bar">
          <div class="pc-fill" :style="{ width: Math.min(rollbackCost * 100, 100) + '%' }" :class="rollbackCost > 0.3 ? 'high' : rollbackCost > 0.15 ? 'mid' : 'low'"></div>
        </div>
        <div class="pc-value">{{ (rollbackCost * 100).toFixed(1) }}%</div>
        <div class="pc-sub">回滚 {{ (dash.summary.manual_rollback || 0) + (dash.summary.auto_rollback || 0) }} / 提交 {{ dash.summary.submit || 0 }}</div>
      </div>
      <div class="ring-card">
        <svg viewBox="0 0 120 120" class="ring-svg">
          <circle cx="60" cy="60" r="48" fill="none" stroke="var(--c-border)" stroke-width="8"/>
          <circle cx="60" cy="60" r="48" fill="none" stroke="#0071e3" stroke-width="8"
            :stroke-dasharray="302" :stroke-dashoffset="302 * (1 - avgConfidence)" transform="rotate(-90 60 60)" stroke-linecap="round"/>
          <text x="60" y="52" text-anchor="middle" fill="var(--c-text-1)" font-size="22" font-weight="700">{{ Math.round(avgConfidence * 100) }}%</text>
          <text x="60" y="72" text-anchor="middle" fill="var(--c-text-2)" font-size="11">变更置信度</text>
        </svg>
        <div class="ring-sub" v-if="confActorCount">基于 {{ confActorCount }} 个操作人</div>
      </div>
      <div class="num-card bypass">
        <div class="num-val">{{ dash.summary.expert_bypass || 0 }}</div>
        <div class="num-lbl">专家绕过</div>
        <div class="num-sub">绕过保护期操作</div>
      </div>
      <div class="num-card drift">
        <div class="num-val">{{ dash.summary.drift_count || 0 }}</div>
        <div class="num-lbl">漂移事件</div>
        <div class="num-sub">自愈 {{ dash.summary.self_heal || 0 }}</div>
      </div>
    </div>

    <!-- 双轴趋势图 -->
    <div class="chart-row">
      <div class="chart-head">
        <span class="chart-title">变更趋势</span>
        <el-radio-group v-model="dashDays" size="small" @change="loadDashboard">
          <el-radio-button :value="7">7天</el-radio-button>
          <el-radio-button :value="30">30天</el-radio-button>
        </el-radio-group>
      </div>
      <div ref="chartRef" class="chart-container" v-loading="dashLoading"></div>
    </div>

    <!-- 时间线 -->
    <div class="tl-section">
      <div class="tl-head">
        <span class="tl-title">审计日志</span>
        <div class="tl-filters">
          <el-input v-model="filter.action" placeholder="动作" clearable size="small" style="width:140px" />
          <el-input v-model="filter.nodeID" placeholder="节点" clearable size="small" style="width:120px" />
          <el-select v-model="filter.scene" placeholder="场景" clearable size="small" style="width:120px">
            <el-option label="常规变更" value="normal" />
            <el-option label="专家绕过" value="expert_bypass" />
            <el-option label="超时回滚" value="auto_rollback" />
            <el-option label="系统自愈" value="self_heal" />
          </el-select>
          <el-button size="small" type="primary" @click="handleSearch" :disabled="loading">搜索</el-button>
          <el-button size="small" @click="handleReset" :disabled="loading">重置</el-button>
          <el-button size="small" @click="handleExport" :loading="exporting">导出</el-button>
        </div>
      </div>
      <div v-loading="loading" class="tl-body">
        <div v-if="!groups.length && !loading" class="tl-empty">暂无审计日志</div>
        <div v-else class="tl-list">
          <div v-for="g in groups" :key="g.key" class="tl-group" :class="groupGlow(g)">
            <div class="tl-axis">
              <span class="tl-dot" :class="groupDot(g)"></span>
              <span class="tl-line"></span>
            </div>
            <div class="tl-content">
              <div class="tl-row">
                <span class="tl-actor">{{ g.actor === 'system' ? '🤖 系统' : '👤 ' + g.actor }}</span>
                <span class="tl-node">🖥 {{ g.nodeIP }}</span>
                <span class="tl-time">{{ g.relativeTime }}</span>
                <span class="tl-badge" :class="groupBadge(g)">{{ g.badgeLabel }}</span>
              </div>
              <div class="tl-detail" @click="handleView(g.firstLog)">
                <span class="tl-action">{{ g.actionLabel }}</span>
                <span class="tl-desc">{{ g.summary }}</span>
              </div>
              <div v-if="g.logs.length > 1" class="tl-sublogs">
                <div v-for="sub in g.sublogs" :key="sub.id" class="tl-subitem" @click="handleView(sub)">
                  <span class="sub-action">{{ getActionLabel(sub.action) }}</span>
                  <span class="sub-desc">{{ summarizeDetail(sub) }}</span>
                  <span class="sub-time">{{ formatRelative(sub.created_at) }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="tl-pagination">
        <el-pagination small :current-page="currentPage" :page-size="pageSize" :total="total"
          @size-change="handleSizeChange" @current-change="handleCurrentChange"
          layout="total, sizes, prev, pager, next" />
      </div>
    </div>

    <!-- 毛玻璃抽屉 -->
    <teleport to="body">
      <transition name="drawer">
        <div v-if="drawerVisible" class="drawer-overlay" @click.self="drawerVisible = false">
          <div class="drawer-panel">
            <div class="drawer-head">
              <span>审计详情</span>
              <el-button size="small" text @click="drawerVisible = false">
                <el-icon><Close /></el-icon>
              </el-button>
            </div>
            <div class="drawer-body">
              <div class="detail-card dcard-action">
                <div class="dc-label">动作</div>
                <div class="dc-value">{{ getActionLabel(viewLog.action) }}</div>
              </div>
              <div class="detail-row">
                <div class="detail-card">
                  <div class="dc-label">场景</div>
                  <div class="dc-value">{{ sceneLabel(viewLog.scene) }}</div>
                </div>
                <div class="detail-card">
                  <div class="dc-label">结果</div>
                  <div class="dc-value">{{ resultLabel(viewLog.result) }}</div>
                </div>
              </div>
              <div class="detail-row">
                <div class="detail-card">
                  <div class="dc-label">操作者</div>
                  <div class="dc-value">{{ viewLog.actor || '-' }}</div>
                </div>
                <div class="detail-card">
                  <div class="dc-label">节点</div>
                  <div class="dc-value">{{ nodeIP(viewLog.node_id) }}</div>
                </div>
              </div>
              <div class="detail-card" v-if="viewLog.protection_window">
                <div class="dc-label">保护期剩余</div>
                <div class="dc-value">{{ viewLog.protection_window }} 秒</div>
              </div>
              <div class="detail-card dcard-full">
                <div class="dc-label">时间</div>
                <div class="dc-value">{{ formatTime(viewLog.created_at) }}</div>
              </div>
              <div class="detail-card dcard-full">
                <div class="dc-label">完整详情</div>
                <pre class="detail-json">{{ prettyDetail(viewLog.detail) }}</pre>
              </div>
            </div>
          </div>
        </div>
      </transition>
    </teleport>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import { Close } from '@element-plus/icons-vue'
import { getAuditLogs, exportAuditLogs, getAuditDashboard, getAuditConfidence, getNodes } from '@/api'
import { useEcharts } from '@/composables/useEcharts'

// --- 数据 ---
const loading = ref(false)
const exporting = ref(false)
const dashLoading = ref(false)
const filter = reactive({ action: '', nodeID: '', scene: '' })
const currentPage = ref(1)
const pageSize = ref(50)
const total = ref(0)
const logs = ref([])
const nodeMap = ref({})
const nodeIP = (id) => nodeMap.value[id] || id || '-'
const dashDays = ref(7)
const dash = ref({ summary: {}, distribution: {}, daily: [], health_rate: 0, rollback_cost: 0 })
const confidence = ref({ by_actor: {}, by_node: {}, by_policy: {} })

// --- 环图计算 ---
const healthRate = computed(() => dash.value.health_rate || 0)
const rollbackCost = computed(() => dash.value.rollback_cost || 0)
const healthColor = computed(() => {
  const r = healthRate.value
  if (r >= 0.8) return '#34c759'
  if (r >= 0.6) return '#ff9f0a'
  return '#ff3b30'
})
const avgConfidence = computed(() => {
  const items = Object.values(confidence.value.by_actor || {})
  if (!items.length) return 0
  return items.reduce((s, v) => s + v.confidence, 0) / items.length
})
const confActorCount = computed(() => Object.keys(confidence.value.by_actor || {}).length)

// --- 时间线分组 ---
const groups = computed(() => {
  if (!logs.value.length) return []
  const m = new Map()
  for (const log of logs.value) {
    const key = log.task_id || ('no-task-' + log.id)
    if (!m.has(key)) {
      m.set(key, { key, logs: [], nodeIP: nodeIP(log.node_id), firstTime: log.created_at, actor: log.actor || '-', isExpert: false })
    }
    const g = m.get(key)
    g.logs.push(log)
    if (log.created_at < g.firstTime) g.firstTime = log.created_at
    if (log.scene === 'expert_bypass') g.isExpert = true
  }
  return Array.from(m.values()).map(g => {
    const last = g.logs[g.logs.length - 1]
    const first = g.logs[0]
    g.firstLog = first
    g.lastAction = last.action
    g.actionLabel = getActionLabel(last.action)
    g.badgeLabel = statusLabel(last.action)
    g.relativeTime = formatRelative(last.created_at)
    g.summary = summarizeDetail(first)
    g.sublogs = g.logs.length > 1 ? g.logs.slice(1) : []
    g.taskLabel = g.key.startsWith('no-task') ? '非任务操作' : g.key.slice(0, 14)
    return g
  })
})
const groupGlow = (g) => {
  const a = g.lastAction
  if (a === 'task.confirm') return 'glow-success'
  if (a === 'task.manual_rollback' || a === 'task.auto_rollback') return 'glow-rollback'
  if (a === 'iptables.exec') return 'glow-expert'
  if (a === 'task.apply_failed' || a === 'task.reject') return 'glow-failed'
  return ''
}
const groupDot = (g) => {
  const a = g.lastAction
  if (a === 'task.confirm') return 'dot-success'
  if (a === 'task.manual_rollback' || a === 'task.auto_rollback') return 'dot-rollback'
  if (a === 'iptables.exec') return 'dot-expert'
  if (a === 'task.apply_failed' || a === 'task.reject') return 'dot-failed'
  return 'dot-info'
}
const groupBadge = (g) => {
  const a = g.lastAction
  if (a === 'task.confirm') return 'badge-success'
  if (a === 'task.manual_rollback' || a === 'task.auto_rollback') return 'badge-rollback'
  if (a === 'iptables.exec') return 'badge-expert'
  if (a === 'task.apply_failed' || a === 'task.reject') return 'badge-failed'
  return 'badge-info'
}
const statusLabel = (a) => {
  if (a === 'task.confirm') return '生效'
  if (a === 'task.manual_rollback' || a === 'task.auto_rollback') return '回滚'
  if (a === 'iptables.exec') return '绕过'
  if (a === 'task.apply_failed' || a === 'task.reject') return '失败'
  return '进行中'
}

// --- 工具函数 ---
const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册', 'node.drift': '规则漂移', 'node.heartbeat': '节点心跳',
    'node.archived': '节点归档', 'node.auto_reregister': '自动重注册',
    'policy.create': '策略创建', 'policy.update': '策略更新', 'policy.delete': '策略删除', 'policy.apply': '策略应用',
    'task.submit': '任务提交', 'task.approve': '任务审批', 'task.reject': '任务拒绝',
    'task.confirm': '确认下发', 'task.auto_rollback': '自动回滚', 'task.manual_rollback': '手动回滚',
    'task.applying_ok': '应用成功', 'task.apply_failed': '应用失败', 'task.recover_failed': '恢复失败',
    'iptables.exec': '专家命令', 'auth.login': '用户登录', 'bootstrap.create': '令牌生成'
  }
  return map[action] || action || '-'
}
const sceneLabel = (s) => ({ normal: '常规变更', expert_bypass: '专家绕过', auto_rollback: '超时回滚', recovery: '启动恢复', self_heal: '系统自愈' }[s] || s || '-')
const resultLabel = (r) => ({ success: '成功', failed: '失败', rolled_back: '已回滚', pending: '进行中' }[r] || r || '-')
const formatTime = (t) => { if (!t) return '-'; try { return new Date(t).toLocaleString() } catch { return t } }
const formatRelative = (t) => {
  if (!t) return '-'
  const diff = Date.now() - new Date(t).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return s + '秒前'
  const m = Math.floor(s / 60)
  if (m < 60) return m + '分钟前'
  const h = Math.floor(m / 60)
  if (h < 24) return h + '小时前'
  const d = Math.floor(h / 24)
  return d + '天前'
}
const parseDetail = (s) => { if (!s) return null; try { return JSON.parse(s) } catch { return null } }
const summarizeDetail = (row) => {
  const d = parseDetail(row.detail)
  if (!d) return row.detail || '-'
  switch (row.action) {
    case 'iptables.exec': return d.command || '-'
    case 'task.submit': return `${d.auto_confirm ? '[自愈] ' : ''}策略#${d.policy_id || '-'}${d.auto_approve ? '(自动审批)' : ''}`
    case 'task.applying_ok': return d.hash ? '哈希 ' + String(d.hash).slice(0, 12) : '成功'
    default: return row.detail || '-'
  }
}
const prettyDetail = (s) => { const d = parseDetail(s); if (!d) return s || '-'; try { return JSON.stringify(d, null, 2) } catch { return s } }

// --- 抽屉 ---
const drawerVisible = ref(false)
const viewLog = reactive({ id: '', action: '', actor: '', node_id: '', task_id: '', detail: '', created_at: '', scene: '', result: '', protection_window: 0 })
const handleView = (log) => { Object.assign(viewLog, log); drawerVisible.value = true }

// --- ECharts ---
const chartRef = ref(null)
const { setOption } = useEcharts(chartRef)
const renderChart = () => {
  const daily = dash.value.daily || []
  if (!daily.length) return
  const dates = daily.map(d => d.date.slice(5))
  const successRates = daily.map(d => {
    const total = d.confirm + d.rollback
    return total > 0 ? Math.round((d.confirm / total) * 100) : 0
  })
  setOption({
    color: ['#0071e3', '#34c759', '#ff9f0a', '#af52de'],
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { data: ['提交', '确认', '回滚', '成功率'], bottom: 0, textStyle: { color: '#6e6e73' } },
    grid: { left: 50, right: 50, top: 16, bottom: 40 },
    xAxis: { type: 'category', data: dates, axisLabel: { color: '#6e6e73', fontSize: 11 }, axisLine: { lineStyle: { color: 'rgba(0,0,0,0.08)' } }, axisTick: { show: false } },
    yAxis: [
      { type: 'value', name: '次数', nameTextStyle: { color: '#6e6e73', fontSize: 11 }, axisLabel: { color: '#6e6e73' }, splitLine: { lineStyle: { color: 'rgba(0,0,0,0.04)', type: 'dashed' } } },
      { type: 'value', name: '成功率 %', max: 100, nameTextStyle: { color: '#6e6e73', fontSize: 11 }, axisLabel: { color: '#6e6e73', formatter: '{value}%' }, splitLine: { show: false } }
    ],
    series: [
      { name: '提交', type: 'bar', data: daily.map(d => d.submit), barWidth: 10, itemStyle: { borderRadius: [3, 3, 0, 0] } },
      { name: '确认', type: 'bar', data: daily.map(d => d.confirm), barWidth: 10, itemStyle: { borderRadius: [3, 3, 0, 0] } },
      { name: '回滚', type: 'bar', data: daily.map(d => d.rollback), barWidth: 10, itemStyle: { borderRadius: [3, 3, 0, 0] } },
      { name: '成功率', type: 'line', yAxisIndex: 1, data: successRates, symbol: 'circle', symbolSize: 6, lineStyle: { width: 2 }, smooth: true }
    ]
  })
}
watch(() => dash.value.daily, (v) => { if (v && v.length) nextTick(renderChart) }, { deep: true })

// --- 加载 ---
const loadNodes = async () => {
  try {
    const data = await getNodes()
    const list = data.nodes || data.data || []
    const m = {}; list.forEach((n) => { m[n.id] = n.ip })
    nodeMap.value = m
  } catch {}
}
const loadDashboard = async () => {
  dashLoading.value = true
  try { dash.value = await getAuditDashboard(dashDays.value) } catch {} finally { dashLoading.value = false }
}
const loadConfidence = async () => {
  try { confidence.value = await getAuditConfidence(30) } catch {}
}
const loadLogs = async () => {
  loading.value = true
  try {
    const params = { limit: pageSize.value, offset: (currentPage.value - 1) * pageSize.value }
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID
    if (filter.scene) params.scene = filter.scene
    const data = await getAuditLogs(params)
    logs.value = data.data || []
    total.value = data.total || 0
  } catch { logs.value = []; total.value = 0 } finally { loading.value = false }
}
const handleSearch = () => { currentPage.value = 1; loadLogs() }
const handleReset = () => { filter.action = ''; filter.nodeID = ''; filter.scene = ''; currentPage.value = 1; loadLogs() }
const handleExport = async () => {
  exporting.value = true
  try {
    const params = {}
    if (filter.action) params.action = filter.action; if (filter.nodeID) params.node_id = filter.nodeID
    if (filter.scene) params.scene = filter.scene
    const blob = await exportAuditLogs(params)
    const url = window.URL.createObjectURL(blob); const a = document.createElement('a')
    a.href = url; a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`; a.click()
    window.URL.revokeObjectURL(url); ElMessage.success('导出成功')
  } catch { ElMessage.error('导出失败') } finally { exporting.value = false }
}
const handleSizeChange = (v) => { pageSize.value = v; currentPage.value = 1; loadLogs() }
const handleCurrentChange = (v) => { currentPage.value = v; loadLogs() }
onMounted(() => { loadNodes(); loadDashboard(); loadConfidence(); loadLogs() })
</script>

<style scoped>
/* 深色主题作用域变量 */
.audit-dashboard {
  display: flex; flex-direction: column; gap: 16px;
  background: var(--c-bg); min-height: 100%; padding: 20px;
  color: var(--c-text-1); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

/* 顶部统计行 */
.stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.audit-dashboard .ring-card,
.audit-dashboard .progress-card,
.audit-dashboard .num-card,
.audit-dashboard .chart-row,
.audit-dashboard .tl-section {
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}
.ring-card, .progress-card, .num-card {
  background: var(--c-surface); border: 1px solid var(--c-border);
  border-radius: 12px; padding: 16px; display: flex; flex-direction: column;
  align-items: center; transition: border-color .2s, box-shadow .2s;
}
.ring-card:hover, .progress-card:hover, .num-card:hover {
  border-color: var(--c-text-2); box-shadow: 0 4px 20px rgba(0,0,0,.3);
}
.ring-svg { width: 100px; height: 100px; }
.ring-sub { font-size: 11px; color: var(--c-text-3); margin-top: 6px; }

/* 进度条卡片 */
.pc-label { font-size: 12px; color: var(--c-text-2); margin-bottom: 8px; }
.pc-bar { width: 100%; height: 8px; background: var(--c-surface-2); border-radius: 4px; overflow: hidden; }
.pc-fill { height: 100%; border-radius: 4px; transition: width .6s ease; }
.pc-fill.low { background: var(--c-success); }
.pc-fill.mid { background: var(--c-warning); }
.pc-fill.high { background: var(--c-danger); }
.pc-value { font-size: 22px; font-weight: 700; margin: 6px 0 2px; color: var(--c-text); }
.pc-sub { font-size: 11px; color: var(--c-text-3); }

/* 数字卡 */
.num-val { font-size: 32px; font-weight: 700; line-height: 1; }
.num-lbl { font-size: 13px; color: var(--c-text-2); margin: 4px 0; }
.num-sub { font-size: 11px; color: var(--c-text-3); }
.num-card.bypass .num-val { color: var(--c-danger); }
.num-card.drift .num-val { color: var(--c-warning); }

/* 图表行 */
.chart-row { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 12px; padding: 16px; }
.chart-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.chart-title { font-size: 15px; font-weight: 600; }
.chart-container { height: 240px; }
.chart-row :deep(.el-radio-button__inner) { background: var(--c-surface-2); border-color: var(--c-border); color: var(--c-text-2); }
.chart-row :deep(.el-radio-button__original-radio:checked + .el-radio-button__inner) { background: var(--c-primary); color: #fff; border-color: var(--c-primary); }

/* 时间线 */
.tl-section { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 12px; padding: 16px; }
.tl-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
.tl-title { font-size: 15px; font-weight: 600; }
.tl-filters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.tl-body { min-height: 120px; }
.tl-empty { text-align: center; color: var(--c-text-3); padding: 40px 0; font-size: 13px; }
.tl-list { display: flex; flex-direction: column; gap: 0; }
.tl-group { display: flex; gap: 14px; padding: 10px 0; position: relative; border-radius: 8px; margin-bottom: 2px; padding-left: 8px; padding-right: 8px; }
/* 状态光晕 */
.glow-success { box-shadow: 0 0 12px rgba(52, 211, 153, 0.15); border: 1px solid rgba(52, 211, 153, 0.2); }
.glow-rollback { border: 1px solid rgba(245, 158, 11, 0.25); }
.glow-expert { border-left: 3px dashed var(--c-danger); }
.glow-failed { border: 1px solid rgba(251, 113, 133, 0.2); }
.tl-axis { display: flex; flex-direction: column; align-items: center; width: 16px; flex-shrink: 0; padding-top: 4px; }
.tl-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; z-index: 1; }
.tl-dot.dot-success { background: var(--c-success); box-shadow: 0 0 6px rgba(52, 211, 153, .5); }
.tl-dot.dot-rollback { background: var(--c-warning); }
.tl-dot.dot-expert { background: var(--c-danger); }
.tl-dot.dot-failed { background: var(--c-danger); }
.tl-dot.dot-info { background: var(--c-text-2); }
.tl-line { flex: 1; width: 2px; background: var(--c-border); margin-top: 4px; }
.tl-group:last-child .tl-line { display: none; }
.tl-content { flex: 1; min-width: 0; }
.tl-row { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--c-text-2); flex-wrap: wrap; }
.tl-actor { color: var(--c-text); }
.tl-node { color: var(--c-primary); }
.tl-time { margin-left: auto; color: var(--c-text-3); font-size: 11px; }
.tl-badge { padding: 1px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-success { background: rgba(52, 211, 153, .15); color: var(--c-success); }
.badge-rollback { background: rgba(245, 158, 11, .15); color: var(--c-warning); }
.badge-expert { background: rgba(251, 113, 133, .15); color: var(--c-danger); }
.badge-failed { background: rgba(251, 113, 133, .15); color: var(--c-danger); }
.badge-info { background: rgba(148, 163, 184, .15); color: var(--c-text-2); }
.tl-detail { display: flex; align-items: center; gap: 8px; margin-top: 4px; cursor: pointer; padding: 4px 8px; border-radius: 6px; transition: background .15s; }
.tl-detail:hover { background: rgba(0, 0, 0, 0.02); }
.tl-action { font-size: 12px; color: var(--c-primary); font-weight: 500; white-space: nowrap; }
.tl-desc { font-size: 13px; color: var(--c-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tl-sublogs { margin-top: 6px; margin-left: 8px; display: flex; flex-direction: column; gap: 4px; }
.tl-subitem { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 3px 8px; border-radius: 4px; cursor: pointer; color: var(--c-text-2); }
.tl-subitem:hover { background: rgba(0, 0, 0, 0.02); }
.sub-action { color: var(--c-text-2); min-width: 80px; }
.sub-desc { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sub-time { color: var(--c-text-3); font-size: 11px; white-space: nowrap; }
.tl-pagination { margin-top: 12px; display: flex; justify-content: flex-end; }
.tl-pagination :deep(.el-pagination) { --el-pagination-button-color: var(--c-text-2); --el-pagination-hover-color: var(--c-primary); }
.tl-pagination :deep(.el-pagination button:disabled) { color: var(--c-text-3); }
.tl-pagination :deep(.el-pager li) { background: transparent; color: var(--c-text-2); }
.tl-pagination :deep(.el-pager li.is-active) { color: var(--c-primary); font-weight: 600; }
.tl-section :deep(.el-input__wrapper), .tl-section :deep(.el-select__wrapper) { background: var(--c-surface-2); border-color: var(--c-border); box-shadow: none; }
.tl-section :deep(.el-input__inner) { color: var(--c-text); }
.tl-section :deep(.el-select__placeholder) { color: var(--c-text-3); }

/* 毛玻璃抽屉 */
.drawer-overlay { position: fixed; inset: 0; z-index: 3000; background: rgba(0,0,0,.4); display: flex; justify-content: flex-end; }
.drawer-panel {
  width: 480px; max-width: 90vw; height: 100%; overflow-y: auto;
  background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(16px);
  border-left: 1px solid var(--c-border); padding: 0;
  display: flex; flex-direction: column;
}
.drawer-head { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--c-border); font-size: 15px; font-weight: 600; color: var(--c-text); }
.drawer-body { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }
.detail-card { background: rgba(0, 0, 0, 0.03); border: 1px solid var(--c-border); border-radius: 8px; padding: 12px; }
.detail-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.dcard-action { background: rgba(0, 113, 227, 0.06); border-color: rgba(0, 113, 227, 0.15); }
.dcard-full { grid-column: 1 / -1; }
.dc-label { font-size: 11px; color: var(--c-text-3); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .04em; }
.dc-value { font-size: 14px; color: var(--c-text); word-break: break-all; }
.detail-json { margin: 0; max-height: 300px; overflow: auto; padding: 8px; background: rgba(0, 0, 0, 0.03); border-radius: 4px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; color: var(--c-text-2); }
.drawer-enter-active, .drawer-leave-active { transition: .25s ease; }
.drawer-enter-active .drawer-panel, .drawer-leave-active .drawer-panel { transition: transform .25s ease; }
.drawer-enter-from { opacity: 0; }
.drawer-enter-from .drawer-panel { transform: translateX(100%); }
.drawer-leave-to { opacity: 0; }
.drawer-leave-to .drawer-panel { transform: translateX(100%); }
</style>