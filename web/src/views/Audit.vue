<template>
  <div class="audit-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审计日志</span>
          <el-button type="primary" @click="handleExport">
            <el-icon><Download /></el-icon>
            导出日志
          </el-button>
        </div>
      </template>
      <div class="filter-bar">
        <el-input v-model="filter.action" placeholder="搜索动作" style="width: 200px; margin-right: 12px" />
        <el-input v-model="filter.nodeID" placeholder="搜索节点ID" style="width: 200px; margin-right: 12px" />
        <el-date-picker v-model="filter.dateRange" type="daterange" range-separator="至" start-placeholder="开始日期" end-placeholder="结束日期" style="width: 300px; margin-right: 12px" />
        <el-button type="primary" @click="handleSearch">搜索</el-button>
        <el-button @click="handleReset">重置</el-button>
      </div>
      <el-table :data="logs" style="width: 100%">
        <el-table-column prop="id" label="日志ID" width="120" />
        <el-table-column prop="action" label="动作" width="150">
          <template #default="{ row }">
            <el-tag :type="getActionTag(row.action)">{{ getActionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="actor" label="操作者" width="120" />
        <el-table-column prop="nodeID" label="节点ID" width="150" />
        <el-table-column prop="detail" label="详情" />
        <el-table-column prop="createdAt" label="时间" width="180" />
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button size="small" @click="handleView(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pagination-row">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
          :current-page="currentPage"
          :page-sizes="[10, 20, 50]"
          :page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <el-dialog v-model="viewDialogVisible" title="日志详情" width="600px">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="日志ID">{{ viewLog.id }}</el-descriptions-item>
        <el-descriptions-item label="动作">{{ getActionLabel(viewLog.action) }}</el-descriptions-item>
        <el-descriptions-item label="操作者">{{ viewLog.actor }}</el-descriptions-item>
        <el-descriptions-item label="节点ID">{{ viewLog.nodeID || '-' }}</el-descriptions-item>
        <el-descriptions-item label="详情">{{ viewLog.detail }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ viewLog.createdAt }}</el-descriptions-item>
        <el-descriptions-item label="IP地址" :span="2">{{ viewLog.ip || '-' }}</el-descriptions-item>
      </el-descriptions>
      <div v-if="viewLog.detailJSON" style="margin-top: 20px">
        <h4>详情JSON</h4>
        <pre>{{ viewLog.detailJSON }}</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'

const filter = reactive({
  action: '',
  nodeID: '',
  dateRange: null
})

const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(100)

const viewDialogVisible = ref(false)

const viewLog = reactive({
  id: '',
  action: '',
  actor: '',
  nodeID: '',
  detail: '',
  createdAt: '',
  ip: '',
  detailJSON: ''
})

const logs = ref([
  { id: 1, action: 'node.register', actor: 'system', nodeID: 'node-001', detail: '节点 node-001 注册成功', createdAt: '2024-01-15 10:30:00', ip: '192.168.1.10', detailJSON: '{"ip":"192.168.1.10","hostname":"prod-server-01"}' },
  { id: 2, action: 'policy.apply', actor: 'admin', nodeID: 'node-001', detail: '策略 policy-001 已应用到节点 node-001', createdAt: '2024-01-15 10:25:00', ip: '192.168.0.1', detailJSON: '{"policy_id":"policy-001","node_id":"node-001","rules":2}' },
  { id: 3, action: 'node.drift', actor: 'agent', nodeID: 'node-002', detail: '检测到节点 node-002 规则漂移', createdAt: '2024-01-15 10:20:00', ip: '-', detailJSON: '{"expected_hash":"abc123","actual_hash":"def456"}' },
  { id: 4, action: 'policy.create', actor: 'admin', nodeID: '', detail: '创建策略 allow-ssh', createdAt: '2024-01-15 10:15:00', ip: '192.168.0.1', detailJSON: '{"name":"allow-ssh","rules":1}' },
  { id: 5, action: 'node.heartbeat', actor: 'agent', nodeID: 'node-003', detail: '节点 node-003 心跳正常', createdAt: '2024-01-15 10:10:00', ip: '-', detailJSON: '{"node_id":"node-003"}' },
  { id: 6, action: 'policy.update', actor: 'admin', nodeID: '', detail: '更新策略 allow-ssh', createdAt: '2024-01-15 09:55:00', ip: '192.168.0.1', detailJSON: '{"policy_id":"policy-001","changes":{"source":"192.168.1.0/24"}}' },
  { id: 7, action: 'node.archived', actor: 'admin', nodeID: 'node-004', detail: '节点 node-004 已归档', createdAt: '2024-01-14 18:00:00', ip: '192.168.0.1', detailJSON: '{"node_id":"node-004"}' },
  { id: 8, action: 'policy.delete', actor: 'admin', nodeID: '', detail: '删除策略 temp-test', createdAt: '2024-01-14 10:00:00', ip: '192.168.0.1', detailJSON: '{"policy_id":"policy-005"}' },
  { id: 9, action: 'auth.login', actor: 'admin', nodeID: '', detail: '管理员登录成功', createdAt: '2024-01-15 09:00:00', ip: '192.168.0.1', detailJSON: '{"username":"admin"}' },
  { id: 10, action: 'node.drift', actor: 'agent', nodeID: 'node-001', detail: '检测到节点 node-001 规则漂移，已自动修复', createdAt: '2024-01-15 08:30:00', ip: '-', detailJSON: '{"expected_hash":"abc123","actual_hash":"xyz789","auto_fix":true}' }
])

const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册',
    'node.drift': '规则漂移',
    'node.heartbeat': '节点心跳',
    'node.archived': '节点归档',
    'policy.create': '策略创建',
    'policy.update': '策略更新',
    'policy.delete': '策略删除',
    'policy.apply': '策略应用',
    'auth.login': '用户登录',
    'approve.approve': '审批通过',
    'approve.reject': '审批拒绝'
  }
  return map[action] || action
}

const getActionTag = (action) => {
  if (action.includes('drift')) return 'danger'
  if (action.includes('create') || action.includes('register')) return 'success'
  if (action.includes('update') || action.includes('apply')) return 'warning'
  if (action.includes('delete') || action.includes('archived')) return 'danger'
  if (action.includes('heartbeat')) return 'info'
  return 'default'
}

const handleSearch = () => {
  ElMessage.info('搜索功能开发中')
}

const handleReset = () => {
  Object.assign(filter, { action: '', nodeID: '', dateRange: null })
}

const handleView = (row) => {
  Object.assign(viewLog, row)
  viewDialogVisible.value = true
}

const handleExport = () => {
  ElMessage.success('导出功能开发中')
}

const handleSizeChange = (val) => {
  pageSize.value = val
}

const handleCurrentChange = (val) => {
  currentPage.value = val
}
</script>

<style scoped>
.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}

.pagination-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}

pre {
  background-color: #f3f4f6;
  padding: 16px;
  border-radius: 8px;
  overflow-x: auto;
  font-size: 13px;
}
</style>