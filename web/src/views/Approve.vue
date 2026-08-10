<template>
  <div class="approve-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审批中心</span>
          <div class="header-actions">
            <el-select v-model="filterStatus" placeholder="筛选状态" style="width: 150px" @change="loadTasks">
              <el-option label="待审批" value="pending_approval" />
              <el-option label="待确认" value="confirm_wait" />
              <el-option label="全部" value="" />
              <el-option label="已通过" value="confirmed" />
              <el-option label="已拒绝" value="failed" />
              <el-option label="已回滚" value="rolled_back" />
            </el-select>
            <el-button @click="loadTasks" :loading="loading">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="tasks" style="width: 100%" v-loading="loading">
        <el-table-column label="策略" min-width="160">
          <template #default="{ row }">
            <el-tag v-if="row.auto_confirm" size="small" type="warning" class="mr-1">自愈</el-tag>
            <span class="policy-name">{{ row.policy_name || '(单条规则)' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="目标节点" width="150">
          <template #default="{ row }">
            <span class="mono">{{ nodeIP(row.node_id) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">{{ getStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="审批人" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.reviewer === 'system'" size="small" type="warning">系统自愈</el-tag>
            <span v-else>{{ row.reviewer || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <template v-if="row.status === 'pending_approval'">
              <el-button size="small" type="success" @click="handleApprove(row)">通过</el-button>
              <el-button size="small" type="danger" @click="handleReject(row)">拒绝</el-button>
            </template>
            <template v-else-if="row.status === 'confirm_wait'">
              <el-button size="small" type="success" @click="handleConfirm(row)">确认</el-button>
              <el-button size="small" type="danger" @click="handleRollback(row)">回滚</el-button>
            </template>
            <el-button size="small" @click="handleView(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="viewDialogVisible" title="任务详情" width="600px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="策略">{{ viewTask.policy_name || '(单条规则)' }}</el-descriptions-item>
        <el-descriptions-item label="目标节点">{{ nodeIP(viewTask.node_id) }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(viewTask.status)" size="small">{{ getStatusLabel(viewTask.status) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="审批人">
          <el-tag v-if="viewTask.reviewer === 'system'" size="small" type="warning">系统自愈</el-tag>
          <span v-else>{{ viewTask.reviewer || '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="任务ID" :span="2"><code>{{ viewTask.id }}</code></el-descriptions-item>
        <el-descriptions-item label="消息" :span="2">{{ viewTask.message || '-' }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ formatTime(viewTask.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ formatTime(viewTask.updated_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getTasks, approveTask, rejectTask, confirmTask, rollbackTask, getNodes } from '@/api'

const loading = ref(false)
const filterStatus = ref('pending_approval')
const tasks = ref([])
const nodes = ref([])

const viewDialogVisible = ref(false)
const viewTask = reactive({ id: '', node_id: '', policy_name: '', status: '', message: '', reviewer: '', created_at: '', updated_at: '' })

// 简化状态:对外只显 待审批/已通过/已拒绝/已回滚,中间态统一"处理中"
const getStatusLabel = (status) => ({
  pending_approval: '待审批',
  confirm_wait: '待确认',
  confirmed: '已通过',
  failed: '已拒绝',
  rolled_back: '已回滚',
  approved: '处理中', dispatching: '处理中', applying: '处理中'
}[status] || status)

const getStatusType = (status) => ({
  pending_approval: 'warning',
  confirmed: 'success',
  failed: 'danger',
  rolled_back: 'danger',
  approved: 'info', dispatching: 'info', applying: 'info', confirm_wait: 'info'
}[status] || 'info')

const nodeIP = (id) => {
  const n = nodes.value.find(x => x.id === id)
  return n ? (n.ip || n.hostname || id.slice(0, 12)) : id.slice(0, 12)
}

const formatTime = (time) => {
  if (!time) return '-'
  try { return new Date(time).toLocaleString() } catch { return time }
}

const loadTasks = async () => {
  loading.value = true
  try {
    const params = filterStatus.value ? { status: filterStatus.value } : {}
    const data = await getTasks(params)
    tasks.value = data.tasks || []
  } catch {
    ElMessage.error('加载任务列表失败')
  } finally {
    loading.value = false
  }
}

const loadNodes = async () => {
  try {
    const data = await getNodes()
    nodes.value = data.nodes || []
  } catch {}
}

const handleView = (row) => {
  Object.assign(viewTask, row)
  viewDialogVisible.value = true
}

const handleApprove = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定通过「${row.policy_name || '单条规则'}」应用到 ${nodeIP(row.node_id)}?通过后规则即时生效。`,
      '确认通过',
      { type: 'info', confirmButtonText: '通过', cancelButtonText: '取消' }
    )
    await approveTask(row.id)
    ElMessage.success('已通过,规则已生效')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '审批失败')
  }
}

const handleReject = async (row) => {
  try {
    const { value: reason } = await ElMessageBox.prompt(
      `拒绝「${row.policy_name || '单条规则'}」的原因?`,
      '确认拒绝',
      { type: 'warning', inputPlaceholder: '拒绝原因', confirmButtonText: '拒绝', cancelButtonText: '取消' }
    )
    await rejectTask(row.id, { reason: reason || '' })
    ElMessage.success('已拒绝')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '操作失败')
  }
}

// 保护期内(confirm_wait)的确认/回滚,与顶部角标面板功能对齐
const handleConfirm = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确认「${row.policy_name || '单条规则'}」生效?将保留当前规则。`,
      '确认生效',
      { type: 'success', confirmButtonText: '确认', cancelButtonText: '取消' }
    )
    await confirmTask(row.id)
    ElMessage.success('已确认生效')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '确认失败')
  }
}

const handleRollback = async (row) => {
  try {
    await ElMessageBox.confirm(
      `回滚「${row.policy_name || '单条规则'}」?节点将恢复到变更前状态。`,
      '确认回滚',
      { type: 'warning', confirmButtonText: '回滚', cancelButtonText: '取消' }
    )
    await rollbackTask(row.id)
    ElMessage.success('已回滚')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '回滚失败')
  }
}

onMounted(() => {
  loadNodes()
  loadTasks()
})
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 12px; align-items: center; }
.policy-name { font-weight: 600; color: #1E293B; }
.mono { font-family: 'JetBrains Mono', monospace; }
.mr-1 { margin-right: 4px; }
</style>
