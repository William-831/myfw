<template>
  <div class="approve-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审批中心</span>
          <div class="header-actions">
            <el-select v-model="filterStatus" placeholder="筛选状态" style="width: 150px" @change="loadTasks">
              <el-option label="待审批" value="pending_approval" />
              <el-option label="全部" value="" />
              <el-option label="已通过" value="approved" />
              <el-option label="确认等待" value="confirm_wait" />
              <el-option label="已确认" value="confirmed" />
              <el-option label="已回滚" value="rolled_back" />
              <el-option label="已拒绝" value="failed" />
            </el-select>
            <el-button @click="loadTasks" :loading="loading">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="tasks" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="任务ID" width="260" show-overflow-tooltip />
        <el-table-column prop="node_id" label="目标节点" width="160" show-overflow-tooltip />
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">{{ getStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="消息" show-overflow-tooltip />
        <el-table-column prop="reviewer" label="审批人" width="100" />
        <el-table-column label="创建时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <template v-if="row.status === 'pending_approval'">
              <el-button size="small" type="success" @click="handleApprove(row)">通过</el-button>
              <el-button size="small" type="danger" @click="handleReject(row)">拒绝</el-button>
            </template>
            <template v-else-if="row.status === 'confirm_wait'">
              <el-button size="small" type="primary" @click="handleConfirm(row)">确认</el-button>
            </template>
            <el-button size="small" @click="handleView(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="viewDialogVisible" title="任务详情" width="650px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="任务ID" :span="2">
          <code>{{ viewTask.id }}</code>
        </el-descriptions-item>
        <el-descriptions-item label="目标节点">{{ viewTask.node_id }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(viewTask.status)" size="small">{{ getStatusLabel(viewTask.status) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="版本">{{ viewTask.version }}</el-descriptions-item>
        <el-descriptions-item label="审批人">{{ viewTask.reviewer || '-' }}</el-descriptions-item>
        <el-descriptions-item label="结果Hash" :span="2">{{ viewTask.result_hash || '-' }}</el-descriptions-item>
        <el-descriptions-item label="消息" :span="2">{{ viewTask.message || '-' }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ formatTime(viewTask.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ formatTime(viewTask.updated_at) }}</el-descriptions-item>
        <el-descriptions-item label="确认截止" :span="2">{{ formatTime(viewTask.confirm_deadline) }}</el-descriptions-item>
      </el-descriptions>
      <div v-if="viewTask.diff_before || viewTask.diff_after" style="margin-top: 20px">
        <h4>变更内容</h4>
        <div class="diff-section" v-if="viewTask.diff_before">
          <h5>变更前</h5>
          <pre>{{ viewTask.diff_before }}</pre>
        </div>
        <div class="diff-section" v-if="viewTask.diff_after">
          <h5>变更后</h5>
          <pre>{{ viewTask.diff_after }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getTasks, approveTask, rejectTask, confirmTask } from '@/api'

const loading = ref(false)
const filterStatus = ref('pending_approval')
const tasks = ref([])

const viewDialogVisible = ref(false)
const viewTask = reactive({
  id: '', node_id: '', status: '', version: 0, message: '',
  reviewer: '', result_hash: '', diff_before: '', diff_after: '',
  created_at: '', updated_at: '', confirm_deadline: ''
})

const getStatusLabel = (status) => {
  const map = {
    pending_approval: '待审批',
    approved: '已通过',
    dispatching: '下发中',
    applying: '应用中',
    confirm_wait: '确认等待',
    confirmed: '已确认',
    rolled_back: '已回滚',
    failed: '已拒绝',
    draft: '草稿'
  }
  return map[status] || status
}

const getStatusType = (status) => {
  const map = {
    pending_approval: 'warning',
    approved: 'info',
    dispatching: 'info',
    applying: 'info',
    confirm_wait: 'warning',
    confirmed: 'success',
    rolled_back: 'danger',
    failed: 'danger',
    draft: 'info'
  }
  return map[status] || 'info'
}

const formatTime = (time) => {
  if (!time) return '-'
  try {
    return new Date(time).toLocaleString()
  } catch {
    return time
  }
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

const handleView = (row) => {
  Object.assign(viewTask, row)
  viewDialogVisible.value = true
}

const handleApprove = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定要通过任务 ${row.id.slice(0, 16)}... 吗？`,
      '确认通过',
      { type: 'info', confirmButtonText: '通过', cancelButtonText: '取消' }
    )
    await approveTask(row.id)
    ElMessage.success('审批已通过')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error(err?.response?.data?.error || '审批失败')
    }
  }
}

const handleReject = async (row) => {
  try {
    const { value: reason } = await ElMessageBox.prompt(
      `请输入拒绝原因（任务 ${row.id.slice(0, 16)}...）`,
      '确认拒绝',
      { type: 'warning', inputPlaceholder: '拒绝原因', confirmButtonText: '拒绝', cancelButtonText: '取消' }
    )
    await rejectTask(row.id, { reason: reason || '' })
    ElMessage.success('已拒绝')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error(err?.response?.data?.error || '操作失败')
    }
  }
}

const handleConfirm = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定要确认任务 ${row.id.slice(0, 16)}... 的变更吗？确认后快照将被释放。`,
      '确认变更',
      { type: 'info', confirmButtonText: '确认', cancelButtonText: '取消' }
    )
    await confirmTask(row.id)
    ElMessage.success('已确认')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error(err?.response?.data?.error || '确认失败')
    }
  }
}

onMounted(loadTasks)
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 12px; align-items: center; }
.diff-section { margin-top: 12px; }
.diff-section h5 { margin: 0 0 8px; color: #374151; }
.diff-section pre { background-color: #f3f4f6; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 13px; margin: 0; }
</style>
