<template>
  <div class="audit-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审计日志</span>
          <div class="header-actions">
            <!-- 列设置:勾选要显示的列,默认只展示核心字段 -->
            <el-popover trigger="click" placement="bottom-end" :width="180">
              <template #reference>
                <el-button>
                  <el-icon><Setting /></el-icon>
                  <span>列设置</span>
                </el-button>
              </template>
              <div class="col-options">
                <el-checkbox-group v-model="visibleCols">
                  <div v-for="col in allCols" :key="col.key" class="col-opt">
                    <el-checkbox :label="col.key">{{ col.label }}</el-checkbox>
                  </div>
                </el-checkbox-group>
              </div>
            </el-popover>
            <el-button type="primary" @click="handleExport" :loading="exporting">
              <el-icon><Download /></el-icon>
              <span>导出日志</span>
            </el-button>
          </div>
        </div>
      </template>
      <div class="filter-bar">
        <el-input v-model="filter.action" placeholder="搜索动作" clearable style="width: 200px" />
        <el-input v-model="filter.nodeID" placeholder="搜索节点" clearable style="width: 200px" />
        <el-button type="primary" @click="handleSearch">搜索</el-button>
        <el-button @click="handleReset">重置</el-button>
      </div>
      <el-table
        :data="logs"
        style="width: 100%"
        v-loading="loading"
        row-key="id"
        highlight-current-row
        @row-click="handleView"
      >
        <el-table-column v-if="colVisible('id')" prop="id" label="日志ID" width="80" />
        <el-table-column v-if="colVisible('action')" label="动作" width="120">
          <template #default="{ row }">
            <el-tag :type="getActionTag(row.action)" size="small">{{ getActionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="colVisible('actor')" prop="actor" label="操作者" width="100" />
        <el-table-column v-if="colVisible('node_ip')" label="节点IP" width="140">
          <template #default="{ row }">{{ nodeIP(row.node_id) }}</template>
        </el-table-column>
        <el-table-column v-if="colVisible('detail')" label="详情" show-overflow-tooltip>
          <template #default="{ row }">{{ summarizeDetail(row) }}</template>
        </el-table-column>
        <el-table-column v-if="colVisible('time')" label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column v-if="colVisible('node_id')" prop="node_id" label="节点ID" width="160" show-overflow-tooltip />
        <el-table-column v-if="colVisible('task_id')" prop="task_id" label="任务ID" width="160" show-overflow-tooltip />
      </el-table>
      <div class="pagination-row">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
          :current-page="currentPage"
          :page-sizes="[10, 20, 50, 100]"
          :page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <!-- 点击某条日志弹出完整详情 -->
    <el-drawer v-model="drawerVisible" title="日志详情" direction="rtl" size="520px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="日志ID">{{ viewLog.id }}</el-descriptions-item>
        <el-descriptions-item label="动作">{{ getActionLabel(viewLog.action) }}</el-descriptions-item>
        <el-descriptions-item label="动作标识" :span="2">{{ viewLog.action || '-' }}</el-descriptions-item>
        <el-descriptions-item label="操作者">{{ viewLog.actor || '-' }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(viewLog.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="节点IP">{{ nodeIP(viewLog.node_id) }}</el-descriptions-item>
        <el-descriptions-item label="节点ID">{{ viewLog.node_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="任务ID" :span="2">{{ viewLog.task_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="完整详情" :span="2">
          <pre class="detail-json">{{ prettyDetail(viewLog.detail) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Download, Setting } from '@element-plus/icons-vue'
import { getAuditLogs, exportAuditLogs, getNodes } from '@/api'

const loading = ref(false)
const exporting = ref(false)

const filter = reactive({ action: '', nodeID: '' })
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const logs = ref([])

// 节点 ID -> IP 映射,审计存的 node_id,列表展示成更易读的 IP
const nodeMap = ref({})
const nodeIP = (id) => nodeMap.value[id] || id || '-'

// 可选列:默认只展示核心字段,节点ID/任务ID 默认隐藏
const allCols = [
  { key: 'id', label: '日志ID' },
  { key: 'action', label: '动作' },
  { key: 'actor', label: '操作者' },
  { key: 'node_ip', label: '节点IP' },
  { key: 'detail', label: '详情' },
  { key: 'time', label: '时间' },
  { key: 'node_id', label: '节点ID' },
  { key: 'task_id', label: '任务ID' }
]
const visibleCols = ref(['id', 'action', 'actor', 'node_ip', 'detail', 'time'])
const colVisible = (key) => visibleCols.value.includes(key)

const drawerVisible = ref(false)
const viewLog = reactive({
  id: '', action: '', actor: '', node_id: '', task_id: '', detail: '', created_at: ''
})

// 操作类型中文映射
const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册',
    'node.drift': '规则漂移',
    'node.heartbeat': '节点心跳',
    'node.archived': '节点归档',
    'node.auto_reregister': '节点自动重注册',
    'policy.create': '策略创建',
    'policy.update': '策略更新',
    'policy.delete': '策略删除',
    'policy.apply': '策略应用',
    'task.submit': '任务提交',
    'task.approve': '任务审批',
    'task.reject': '任务拒绝',
    'task.confirm': '任务确认',
    'task.auto_rollback': '自动回滚',
    'task.applying_ok': '规则应用成功',
    'task.apply_failed': '规则应用失败',
    'task.recover_failed': '恢复失败',
    'iptables.exec': '专家命令',
    'auth.login': '用户登录',
    'bootstrap.create': '令牌生成'
  }
  return map[action] || action
}

const getActionTag = (action) => {
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback')) return 'danger'
  if (action.includes('create') || action.includes('register') || action.includes('ok')) return 'success'
  if (action.includes('update') || action.includes('apply') || action.includes('approve') || action.includes('submit') || action.includes('exec')) return 'warning'
  if (action.includes('delete') || action.includes('archived')) return 'danger'
  if (action.includes('heartbeat')) return 'info'
  return 'default'
}

const formatTime = (time) => {
  if (!time) return '-'
  try {
    return new Date(time).toLocaleString()
  } catch {
    return time
  }
}

// detail 字段统一存 JSON 字符串,解析失败回退原文
const parseDetail = (s) => {
  if (!s) return null
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

// 详情列只展示与操作相关的精简摘要:命令下发记命令,CRUD 记动作+策略名
const summarizeDetail = (row) => {
  const d = parseDetail(row.detail)
  if (!d) return row.detail || '-'
  switch (row.action) {
    case 'iptables.exec':
      return d.command || '-'
    case 'policy.create':
      return `创建策略 ${d.name || '#' + d.policy_id}`
    case 'policy.update':
      return `更新策略 ${d.name || '#' + d.policy_id}`
    case 'policy.delete':
      return `删除策略 ${d.name || '#' + d.policy_id}`
    case 'task.submit':
      return `策略#${d.policy_id || '-'}${d.auto_approve ? '(自动审批)' : ''}`
    case 'task.reject':
      return d.reason || '已拒绝'
    case 'task.apply_failed':
      return d.msg || '应用失败'
    case 'task.applying_ok':
      return d.hash ? '哈希 ' + String(d.hash).slice(0, 12) : '成功'
    case 'node.drift':
      return d.detail || '规则漂移'
    case 'node.register':
      return d.fingerprint ? '指纹 ' + String(d.fingerprint).slice(0, 12) : '注册'
    default:
      return row.detail || '-'
  }
}

// 展开行展示完整 detail,JSON 美化便于排查
const prettyDetail = (s) => {
  const d = parseDetail(s)
  if (!d) return s || '-'
  try {
    return JSON.stringify(d, null, 2)
  } catch {
    return s
  }
}

const loadNodes = async () => {
  try {
    const data = await getNodes()
    const list = data.nodes || data.data || []
    const m = {}
    list.forEach((n) => { m[n.id] = n.ip })
    nodeMap.value = m
  } catch {
    // 节点列表加载失败不影响审计展示,回退显示 node_id
  }
}

const loadLogs = async () => {
  loading.value = true
  try {
    const params = {
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value
    }
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID

    const data = await getAuditLogs(params)
    logs.value = data.data || []
    total.value = data.total || 0
  } catch {
    logs.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  currentPage.value = 1
  loadLogs()
}

const handleReset = () => {
  filter.action = ''
  filter.nodeID = ''
  currentPage.value = 1
  loadLogs()
}

const handleView = (row) => {
  Object.assign(viewLog, row)
  drawerVisible.value = true
}

const handleExport = async () => {
  exporting.value = true
  try {
    const params = {}
    if (filter.action) params.action = filter.action
    if (filter.nodeID) params.node_id = filter.nodeID

    const blob = await exportAuditLogs(params)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch {
    ElMessage.error('导出失败')
  } finally {
    exporting.value = false
  }
}

const handleSizeChange = (val) => {
  pageSize.value = val
  currentPage.value = 1
  loadLogs()
}

const handleCurrentChange = (val) => {
  currentPage.value = val
  loadLogs()
}

onMounted(() => {
  loadNodes()
  loadLogs()
})
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; align-items: center; gap: 12px; }
.filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.pagination-row { display: flex; justify-content: flex-end; margin-top: 16px; }
.col-options { display: flex; flex-direction: column; gap: 6px; }
.col-opt { padding: 2px 0; }
.detail-json {
  margin: 0;
  max-height: 360px;
  overflow: auto;
  padding: 8px;
  background: var(--el-fill-color-light, #f5f7fa);
  border-radius: 4px;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
