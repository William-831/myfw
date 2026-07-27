<template>
  <div class="audit-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审计日志</span>
          <el-button type="primary" @click="handleExport" :loading="exporting">
            <el-icon><Download /></el-icon>
            导出日志
          </el-button>
        </div>
      </template>
      <div class="filter-bar">
        <el-input v-model="filter.action" placeholder="搜索动作" clearable style="width: 200px" />
        <el-input v-model="filter.nodeID" placeholder="搜索节点ID" clearable style="width: 200px" />
        <el-button type="primary" @click="handleSearch">搜索</el-button>
        <el-button @click="handleReset">重置</el-button>
      </div>
      <el-table :data="logs" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="日志ID" width="80" />
        <el-table-column label="动作" width="140">
          <template #default="{ row }">
            <el-tag :type="getActionTag(row.action)" size="small">{{ getActionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="actor" label="操作者" width="100" />
        <el-table-column prop="node_id" label="节点ID" width="160" show-overflow-tooltip />
        <el-table-column prop="task_id" label="任务ID" width="160" show-overflow-tooltip />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
        <el-table-column label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button size="small" text @click="handleView(row)">详情</el-button>
          </template>
        </el-table-column>
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

    <el-dialog v-model="viewDialogVisible" title="日志详情" width="600px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="日志ID">{{ viewLog.id }}</el-descriptions-item>
        <el-descriptions-item label="动作">{{ getActionLabel(viewLog.action) }}</el-descriptions-item>
        <el-descriptions-item label="操作者">{{ viewLog.actor }}</el-descriptions-item>
        <el-descriptions-item label="节点ID">{{ viewLog.node_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="任务ID" :span="2">{{ viewLog.task_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="详情" :span="2">{{ viewLog.detail }}</el-descriptions-item>
        <el-descriptions-item label="创建时间" :span="2">{{ formatTime(viewLog.created_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'
import { getAuditLogs, exportAuditLogs } from '@/api'

const loading = ref(false)
const exporting = ref(false)

const filter = reactive({ action: '', nodeID: '' })
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const logs = ref([])

const viewDialogVisible = ref(false)
const viewLog = reactive({
  id: '', action: '', actor: '', node_id: '', task_id: '', detail: '', created_at: ''
})

const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册',
    'node.drift': '规则漂移',
    'node.heartbeat': '节点心跳',
    'node.archived': '节点归档',
    'policy.create': '策略创建',
    'policy.update': '策略更新',
    'policy.delete': '策略删除',
    'task.submit': '任务提交',
    'task.approve': '任务审批',
    'task.reject': '任务拒绝',
    'task.confirm': '任务确认',
    'task.auto_rollback': '自动回滚',
    'task.applying_ok': '规则应用成功',
    'task.apply_failed': '规则应用失败',
    'task.recover_failed': '恢复失败',
    'auth.login': '用户登录',
    'bootstrap.create': '令牌生成'
  }
  return map[action] || action
}

const getActionTag = (action) => {
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback')) return 'danger'
  if (action.includes('create') || action.includes('register') || action.includes('ok')) return 'success'
  if (action.includes('update') || action.includes('apply') || action.includes('approve') || action.includes('submit')) return 'warning'
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
  viewDialogVisible.value = true
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

onMounted(loadLogs)
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.pagination-row { display: flex; justify-content: flex-end; margin-top: 16px; }
</style>
