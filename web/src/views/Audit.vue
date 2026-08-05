<template>
  <div class="audit-page">
    <!-- 保护期变更仪表盘 -->
    <el-card class="dashboard-card">
      <template #header>
        <div class="header-row">
          <span>保护期变更仪表盘</span>
          <el-radio-group v-model="dashDays" size="small" @change="loadDashboard">
            <el-radio-button :value="7">近 7 天</el-radio-button>
            <el-radio-button :value="30">近 30 天</el-radio-button>
          </el-radio-group>
        </div>
      </template>
      <div v-loading="dashLoading" class="dashboard-body">
        <div class="stat-cards">
          <div class="stat-card total">
            <div class="stat-label">总变更</div>
            <div class="stat-value">{{ dash.summary.total || 0 }}</div>
            <div class="stat-sub">提交 {{ dash.summary.submit || 0 }} + 专家 {{ dash.summary.expert_bypass || 0 }}</div>
          </div>
          <div class="stat-card success">
            <div class="stat-label">确认生效</div>
            <div class="stat-value">{{ dash.summary.confirmed || 0 }}</div>
            <div class="stat-sub">保护期内确认</div>
          </div>
          <div class="stat-card rollback">
            <div class="stat-label">回滚</div>
            <div class="stat-value">{{ (dash.summary.manual_rollback || 0) + (dash.summary.auto_rollback || 0) }}</div>
            <div class="stat-sub">手动 {{ dash.summary.manual_rollback || 0 }} / 超时 {{ dash.summary.auto_rollback || 0 }}</div>
          </div>
          <div class="stat-card expert">
            <div class="stat-label">专家绕过</div>
            <div class="stat-value">{{ dash.summary.expert_bypass || 0 }}</div>
            <div class="stat-sub">绕过保护期操作</div>
          </div>
        </div>
        <div class="dash-row">
          <div class="dash-block">
            <div class="block-title">保护期变更终态分布</div>
            <div class="dist-bar">
              <div v-for="d in distribution" :key="d.key" class="dist-seg" :class="d.key"
                :style="{ width: distWidth(d.value) }" :title="d.label + ': ' + d.value">
                <span v-if="d.value > 0">{{ d.label }} {{ d.value }}</span>
              </div>
            </div>
            <div v-if="distTotal === 0" class="empty-tip">暂无数据</div>
          </div>
          <div class="dash-block">
            <div class="block-title">按天趋势</div>
            <div class="trend-chart">
              <div v-for="d in dash.daily" :key="d.date" class="trend-col">
                <div class="trend-bars">
                  <div class="bar submit" :style="{ height: barHeight(d.submit) }" :title="'提交 ' + d.submit"></div>
                  <div class="bar confirm" :style="{ height: barHeight(d.confirm) }" :title="'确认 ' + d.confirm"></div>
                  <div class="bar rollback" :style="{ height: barHeight(d.rollback) }" :title="'回滚 ' + d.rollback"></div>
                  <div class="bar expert" :style="{ height: barHeight(d.expert) }" :title="'专家 ' + d.expert"></div>
                </div>
                <div class="trend-date">{{ d.date.slice(5) }}</div>
              </div>
            </div>
            <div class="legend">
              <span><span class="dot submit"></span>提交</span>
              <span><span class="dot confirm"></span>确认</span>
              <span><span class="dot rollback"></span>回滚</span>
              <span><span class="dot expert"></span>专家</span>
            </div>
          </div>
        </div>
      </div>
    </el-card>

    <el-card>
      <template #header>
        <div class="header-row">
          <span>审计日志(按任务聚合)</span>
          <el-button type="primary" @click="handleExport" :loading="exporting">
            <el-icon><Download /></el-icon><span>导出日志</span>
          </el-button>
        </div>
      </template>
      <div class="filter-bar">
        <el-input v-model="filter.action" placeholder="搜索动作(如 task.confirm)" clearable style="width: 220px" />
        <el-input v-model="filter.nodeID" placeholder="搜索节点" clearable style="width: 200px" />
        <el-select v-model="filter.scene" placeholder="场景" clearable style="width: 150px">
          <el-option label="常规变更" value="normal" />
          <el-option label="专家绕过" value="expert_bypass" />
          <el-option label="超时回滚" value="auto_rollback" />
          <el-option label="启动恢复" value="recovery" />
        </el-select>
        <el-select v-model="filter.result" placeholder="结果" clearable style="width: 130px">
          <el-option label="成功" value="success" />
          <el-option label="失败" value="failed" />
          <el-option label="已回滚" value="rolled_back" />
          <el-option label="进行中" value="pending" />
        </el-select>
        <el-button type="primary" @click="handleSearch">搜索</el-button>
        <el-button @click="handleReset">重置</el-button>
      </div>
      <div v-loading="loading" class="audit-groups">
        <div v-if="!groups.length && !loading" class="empty">暂无日志</div>
        <el-collapse v-model="activeGroups">
          <el-collapse-item v-for="g in groups" :key="g.key" :name="g.key">
            <template #title>
              <div class="group-title">
                <span v-if="g.isExpert" class="bypass-badge">🚫 绕过保护期</span>
                <span class="g-name">{{ g.label }}</span>
                <span class="g-node">📍 {{ g.nodeIP }}</span>
                <span class="g-time">{{ formatTime(g.firstTime) }}</span>
                <el-tag size="small" :type="getActionTag(g.lastAction)">{{ getActionLabel(g.lastAction) }}</el-tag>
                <span class="g-count">{{ g.logs.length }} 条</span>
              </div>
            </template>
            <div class="group-logs">
              <div v-for="log in g.logs" :key="log.id" class="log-item" :class="{ 'log-expert': log.scene === 'expert_bypass' }" @click="handleView(log)">
                <span class="log-time">{{ formatTime(log.created_at) }}</span>
                <el-tag size="small" :type="getActionTag(log.action)">{{ getActionLabel(log.action) }}</el-tag>
                <el-tag v-if="log.scene" size="small" :type="sceneTag(log.scene)" effect="plain">{{ sceneLabel(log.scene) }}</el-tag>
                <span class="log-actor">👤 {{ log.actor || '-' }}</span>
                <span class="log-node">🖥 {{ nodeIP(log.node_id) }}</span>
                <span class="log-detail">{{ summarizeDetail(log) }}</span>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>
      <div class="pagination-row">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
          :current-page="currentPage"
          :page-sizes="[20, 50, 100, 200]"
          :page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <el-drawer v-model="drawerVisible" title="日志详情" direction="rtl" size="520px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="日志ID">{{ viewLog.id }}</el-descriptions-item>
        <el-descriptions-item label="动作">{{ getActionLabel(viewLog.action) }}</el-descriptions-item>
        <el-descriptions-item label="场景">{{ sceneLabel(viewLog.scene) }}</el-descriptions-item>
        <el-descriptions-item label="结果">{{ resultLabel(viewLog.result) }}</el-descriptions-item>
        <el-descriptions-item label="操作者">{{ viewLog.actor || '-' }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(viewLog.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="节点IP">{{ nodeIP(viewLog.node_id) }}</el-descriptions-item>
        <el-descriptions-item label="任务ID">{{ viewLog.task_id || '-' }}</el-descriptions-item>
        <el-descriptions-item v-if="viewLog.protection_window" label="保护期剩余" :span="2">{{ viewLog.protection_window }} 秒</el-descriptions-item>
        <el-descriptions-item label="完整详情" :span="2">
          <pre class="detail-json">{{ prettyDetail(viewLog.detail) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'
import { getAuditLogs, exportAuditLogs, getAuditDashboard, getNodes } from '@/api'

const loading = ref(false)
const exporting = ref(false)
const filter = reactive({ action: '', nodeID: '', scene: '', result: '' })
const currentPage = ref(1)
const pageSize = ref(50)
const total = ref(0)
const logs = ref([])
const activeGroups = ref([])

const nodeMap = ref({})
const nodeIP = (id) => nodeMap.value[id] || id || '-'

// 仪表盘
const dashLoading = ref(false)
const dashDays = ref(7)
const dash = ref({ summary: {}, distribution: {}, daily: [] })

const distribution = computed(() => [
  { key: 'success', label: '生效', value: dash.value.distribution?.success || 0 },
  { key: 'rolled_back', label: '回滚', value: dash.value.distribution?.rolled_back || 0 },
  { key: 'failed', label: '失败', value: dash.value.distribution?.failed || 0 },
  { key: 'pending', label: '进行中', value: dash.value.distribution?.pending || 0 },
])
const distTotal = computed(() => distribution.value.reduce((s, d) => s + d.value, 0))
const distWidth = (v) => {
  if (!distTotal.value) return '0%'
  return (v / distTotal.value) * 100 + '%'
}
const trendMax = computed(() => Math.max(1, ...dash.value.daily.map(d => Math.max(d.submit, d.confirm, d.rollback, d.expert))))
const barHeight = (v) => {
  if (!v) return '0%'
  return Math.max((v / trendMax.value) * 100, 6) + '%'
}

const sceneLabel = (s) => ({ normal: '常规变更', expert_bypass: '专家绕过', auto_rollback: '超时回滚', recovery: '启动恢复' }[s] || s || '-')
const sceneTag = (s) => ({ normal: '', expert_bypass: 'danger', auto_rollback: 'warning', recovery: 'info' }[s] || 'info')
const resultLabel = (r) => ({ success: '成功', failed: '失败', rolled_back: '已回滚', pending: '进行中' }[r] || r || '-')

// 按 task_id 聚合:同一任务的操作序列归一组,无 task_id 的按单条独立成组
const groups = computed(() => {
  const m = new Map()
  for (const log of logs.value) {
    const key = log.task_id || ('no-task-' + log.id)
    if (!m.has(key)) {
      m.set(key, {
        key,
        label: log.task_id ? '任务 ' + String(log.task_id).slice(0, 14) : '非任务操作',
        logs: [],
        nodeIP: nodeIP(log.node_id),
        firstTime: log.created_at,
        lastAction: log.action,
        isExpert: log.scene === 'expert_bypass',
      })
    }
    const g = m.get(key)
    g.logs.push(log)
    if (log.created_at < g.firstTime) g.firstTime = log.created_at
    g.lastAction = log.action
    if (log.scene === 'expert_bypass') g.isExpert = true
  }
  return Array.from(m.values())
})

const drawerVisible = ref(false)
const viewLog = reactive({ id: '', action: '', actor: '', node_id: '', task_id: '', detail: '', created_at: '', scene: '', result: '', protection_window: 0 })

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
const getActionTag = (action) => {
  if (!action) return 'info'
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback') || action.includes('reject')) return 'danger'
  if (action.includes('create') || action.includes('register') || action.includes('ok') || action.includes('confirm')) return 'success'
  if (action.includes('update') || action.includes('apply') || action.includes('approve') || action.includes('submit') || action.includes('exec')) return 'warning'
  if (action.includes('delete') || action.includes('archived')) return 'danger'
  return 'info'
}
const formatTime = (t) => { if (!t) return '-'; try { return new Date(t).toLocaleString() } catch { return t } }
const parseDetail = (s) => { if (!s) return null; try { return JSON.parse(s) } catch { return null } }
const summarizeDetail = (row) => {
  const d = parseDetail(row.detail)
  if (!d) return row.detail || '-'
  switch (row.action) {
    case 'iptables.exec': return d.command || '-'
    case 'task.submit': return `策略#${d.policy_id || '-'}${d.auto_approve ? '(自动审批)' : ''}`
    case 'task.confirm': return d.reason || '已确认生效'
    case 'task.applying_ok': return d.hash ? '哈希 ' + String(d.hash).slice(0, 12) + (d.protection_window ? ` · 保护期 ${d.protection_window}s` : '') : '成功'
    case 'task.apply_failed': return d.msg || '应用失败'
    case 'node.drift': return d.detail || '规则漂移'
    default: return row.detail || '-'
  }
}
const prettyDetail = (s) => { const d = parseDetail(s); if (!d) return s || '-'; try { return JSON.stringify(d, null, 2) } catch { return s } }

const loadNodes = async () => {
  try {
    const data = await getNodes()
    const list = data.nodes || data.data || []
    const m = {}; list.forEach((n) => { m[n.id] = n.ip })
    nodeMap.value = m
  } catch {}
}
const loadLogs = async () => {
  loading.value = true
  try {
    const params = { limit: pageSize.value, offset: (currentPage.value - 1) * pageSize.value }
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID
    if (filter.scene) params.scene = filter.scene
    if (filter.result) params.result = filter.result
    const data = await getAuditLogs(params)
    logs.value = data.data || []
    total.value = data.total || 0
    if (groups.value.length && !activeGroups.value.length) activeGroups.value = [groups.value[0].key]
  } catch { logs.value = []; total.value = 0 } finally { loading.value = false }
}
const loadDashboard = async () => {
  dashLoading.value = true
  try {
    dash.value = await getAuditDashboard(dashDays.value)
  } catch {} finally { dashLoading.value = false }
}
const handleSearch = () => { currentPage.value = 1; loadLogs() }
const handleReset = () => { filter.action = ''; filter.nodeID = ''; filter.scene = ''; filter.result = ''; currentPage.value = 1; loadLogs() }
const handleView = (row) => { Object.assign(viewLog, row); drawerVisible.value = true }
const handleExport = async () => {
  exporting.value = true
  try {
    const params = {}
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID
    if (filter.scene) params.scene = filter.scene
    if (filter.result) params.result = filter.result
    const blob = await exportAuditLogs(params)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`; a.click()
    window.URL.revokeObjectURL(url); ElMessage.success('导出成功')
  } catch { ElMessage.error('导出失败') } finally { exporting.value = false }
}
const handleSizeChange = (v) => { pageSize.value = v; currentPage.value = 1; loadLogs() }
const handleCurrentChange = (v) => { currentPage.value = v; loadLogs() }
onMounted(() => { loadNodes(); loadLogs(); loadDashboard() })
</script>

<style scoped>
.audit-page { display: flex; flex-direction: column; gap: 16px; }
.header-row { display: flex; justify-content: space-between; align-items: center; }
.filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.audit-groups { min-height: 200px; }
.empty { text-align: center; color: #909399; padding: 40px 0; }
.group-title { display: flex; align-items: center; gap: 10px; flex: 1; font-size: 13px; }
.bypass-badge { color: #fff; background: #ef4444; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.g-name { font-weight: 600; color: #1e293b; font-family: 'Courier New', monospace; }
.g-node { color: #2563eb; }
.g-time { color: #94a3b8; font-size: 12px; }
.g-count { margin-left: auto; color: #64748b; font-size: 12px; }
.group-logs { display: flex; flex-direction: column; gap: 6px; padding: 4px 0; }
.log-item {
  display: flex; align-items: center; gap: 10px; padding: 8px 10px;
  border: 1px solid #f1f5f9; border-radius: 6px; font-size: 13px; cursor: pointer;
}
.log-item:hover { background: #f8fafc; }
.log-expert { border-color: #fecaca; background: #fef2f2; }
.log-expert:hover { background: #fee2e2; }
.log-time { color: #64748b; font-size: 12px; min-width: 150px; }
.log-actor { color: #475569; }
.log-node { color: #2563eb; font-family: 'Courier New', monospace; }
.log-detail { color: #475569; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pagination-row { display: flex; justify-content: flex-end; margin-top: 16px; }
.detail-json { margin: 0; max-height: 360px; overflow: auto; padding: 8px; background: var(--el-fill-color-light, #f5f7fa); border-radius: 4px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }

/* 仪表盘 */
.dashboard-body { display: flex; flex-direction: column; gap: 16px; }
.stat-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.stat-card { padding: 16px; border-radius: 8px; border-left: 4px solid; background: #f8fafc; }
.stat-card.total { border-color: #2563eb; }
.stat-card.success { border-color: #10b981; }
.stat-card.rollback { border-color: #f59e0b; }
.stat-card.expert { border-color: #ef4444; }
.stat-label { color: #64748b; font-size: 13px; }
.stat-value { font-size: 28px; font-weight: 700; color: #1e293b; margin: 4px 0; }
.stat-sub { color: #94a3b8; font-size: 12px; }
.dash-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.dash-block { border: 1px solid #f1f5f9; border-radius: 8px; padding: 12px; }
.block-title { font-size: 13px; font-weight: 600; color: #475569; margin-bottom: 12px; }
.dist-bar { display: flex; height: 32px; border-radius: 6px; overflow: hidden; background: #f1f5f9; }
.dist-seg { display: flex; align-items: center; justify-content: center; color: #fff; font-size: 12px; transition: width .3s; min-width: 0; overflow: hidden; white-space: nowrap; }
.dist-seg.success { background: #10b981; }
.dist-seg.rolled_back { background: #f59e0b; }
.dist-seg.failed { background: #ef4444; }
.dist-seg.pending { background: #94a3b8; }
.empty-tip { text-align: center; color: #94a3b8; font-size: 12px; padding: 8px; }
.trend-chart { display: flex; align-items: flex-end; gap: 6px; height: 120px; }
.trend-col { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; }
.trend-bars { display: flex; align-items: flex-end; gap: 2px; flex: 1; width: 100%; justify-content: center; }
.bar { width: 8px; border-radius: 2px 2px 0 0; min-height: 0; transition: height .3s; }
.bar.submit { background: #2563eb; }
.bar.confirm { background: #10b981; }
.bar.rollback { background: #f59e0b; }
.bar.expert { background: #ef4444; }
.trend-date { font-size: 11px; color: #94a3b8; margin-top: 4px; }
.legend { display: flex; gap: 12px; font-size: 12px; color: #64748b; margin-top: 8px; flex-wrap: wrap; }
.legend .dot { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 3px; vertical-align: middle; }
.dot.submit { background: #2563eb; }
.dot.confirm { background: #10b981; }
.dot.rollback { background: #f59e0b; }
.dot.expert { background: #ef4444; }
</style>
