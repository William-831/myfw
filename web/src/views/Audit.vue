<template>
  <div class="audit-page">
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
        <el-button type="primary" @click="handleSearch">搜索</el-button>
        <el-button @click="handleReset">重置</el-button>
      </div>
      <div v-loading="loading" class="audit-groups">
        <div v-if="!groups.length && !loading" class="empty">暂无日志</div>
        <el-collapse v-model="activeGroups">
          <el-collapse-item v-for="g in groups" :key="g.key" :name="g.key">
            <template #title>
              <div class="group-title">
                <span class="g-name">{{ g.label }}</span>
                <span class="g-node">📍 {{ g.nodeIP }}</span>
                <span class="g-time">{{ formatTime(g.firstTime) }}</span>
                <el-tag size="small" :type="getActionTag(g.lastAction)">{{ getActionLabel(g.lastAction) }}</el-tag>
                <span class="g-count">{{ g.logs.length }} 条</span>
              </div>
            </template>
            <div class="group-logs">
              <div v-for="log in g.logs" :key="log.id" class="log-item" @click="handleView(log)">
                <span class="log-time">{{ formatTime(log.created_at) }}</span>
                <el-tag size="small" :type="getActionTag(log.action)">{{ getActionLabel(log.action) }}</el-tag>
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
        <el-descriptions-item label="操作者">{{ viewLog.actor || '-' }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(viewLog.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="节点IP">{{ nodeIP(viewLog.node_id) }}</el-descriptions-item>
        <el-descriptions-item label="任务ID">{{ viewLog.task_id || '-' }}</el-descriptions-item>
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
import { getAuditLogs, exportAuditLogs, getNodes } from '@/api'

const loading = ref(false)
const exporting = ref(false)
const filter = reactive({ action: '', nodeID: '' })
const currentPage = ref(1)
const pageSize = ref(50)
const total = ref(0)
const logs = ref([])
const activeGroups = ref([])

const nodeMap = ref({})
const nodeIP = (id) => nodeMap.value[id] || id || '-'

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
      })
    }
    const g = m.get(key)
    g.logs.push(log)
    // 首条时间取最早,标题动作取最新
    if (log.created_at < g.firstTime) g.firstTime = log.created_at
    g.lastAction = log.action
  }
  return Array.from(m.values())
})

const drawerVisible = ref(false)
const viewLog = reactive({ id: '', action: '', actor: '', node_id: '', task_id: '', detail: '', created_at: '' })

const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册', 'node.drift': '规则漂移', 'node.heartbeat': '节点心跳',
    'node.archived': '节点归档', 'node.auto_reregister': '自动重注册',
    'policy.create': '策略创建', 'policy.update': '策略更新', 'policy.delete': '策略删除', 'policy.apply': '策略应用',
    'task.submit': '任务提交', 'task.approve': '任务审批', 'task.reject': '任务拒绝',
    'task.confirm': '确认下发', 'task.auto_rollback': '自动回滚', 'task.applying_ok': '应用成功',
    'task.apply_failed': '应用失败', 'task.recover_failed': '恢复失败',
    'iptables.exec': '专家命令', 'auth.login': '用户登录', 'bootstrap.create': '令牌生成'
  }
  return map[action] || action || '-'
}
const getActionTag = (action) => {
  if (!action) return 'info'
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback')) return 'danger'
  if (action.includes('create') || action.includes('register') || action.includes('ok') || action.includes('confirm')) return 'success'
  if (action.includes('update') || action.includes('apply') || action.includes('approve') || action.includes('submit') || action.includes('exec')) return 'warning'
  if (action.includes('delete') || action.includes('archived') || action.includes('reject')) return 'danger'
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
    case 'task.applying_ok': return d.hash ? '哈希 ' + String(d.hash).slice(0, 12) : '成功'
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
    const data = await getAuditLogs(params)
    logs.value = data.data || []
    total.value = data.total || 0
    // 默认展开第一个任务组
    if (groups.value.length && !activeGroups.value.length) activeGroups.value = [groups.value[0].key]
  } catch { logs.value = []; total.value = 0 } finally { loading.value = false }
}
const handleSearch = () => { currentPage.value = 1; loadLogs() }
const handleReset = () => { filter.action = ''; filter.nodeID = ''; currentPage.value = 1; loadLogs() }
const handleView = (row) => { Object.assign(viewLog, row); drawerVisible.value = true }
const handleExport = async () => {
  exporting.value = true
  try {
    const params = {}
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID
    const blob = await exportAuditLogs(params)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`; a.click()
    window.URL.revokeObjectURL(url); ElMessage.success('导出成功')
  } catch { ElMessage.error('导出失败') } finally { exporting.value = false }
}
const handleSizeChange = (v) => { pageSize.value = v; currentPage.value = 1; loadLogs() }
const handleCurrentChange = (v) => { currentPage.value = v; loadLogs() }
onMounted(() => { loadNodes(); loadLogs() })
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.audit-groups { min-height: 200px; }
.empty { text-align: center; color: #909399; padding: 40px 0; }
.group-title { display: flex; align-items: center; gap: 10px; flex: 1; font-size: 13px; }
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
.log-time { color: #64748b; font-size: 12px; min-width: 150px; }
.log-actor { color: #475569; }
.log-node { color: #2563eb; font-family: 'Courier New', monospace; }
.log-detail { color: #475569; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pagination-row { display: flex; justify-content: flex-end; margin-top: 16px; }
.detail-json { margin: 0; max-height: 360px; overflow: auto; padding: 8px; background: var(--el-fill-color-light, #f5f7fa); border-radius: 4px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
</style>
