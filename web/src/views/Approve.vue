<template>
  <div class="approve-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>审批中心</span>
          <el-select v-model="filterStatus" placeholder="筛选状态" style="width: 150px">
            <el-option label="全部" value="" />
            <el-option label="待审批" value="pending" />
            <el-option label="已通过" value="approved" />
            <el-option label="已拒绝" value="rejected" />
          </el-select>
        </div>
      </template>
      <el-table :data="filteredApprovals" style="width: 100%">
        <el-table-column prop="id" label="审批ID" width="160" />
        <el-table-column prop="type" label="审批类型" width="120">
          <template #default="{ row }">
            <el-tag :type="getTypeTag(row.type)">{{ getTypeLabel(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="标题" />
        <el-table-column prop="applicant" label="申请人" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusTag(row.status)">{{ getStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="申请时间" width="180" />
        <el-table-column prop="approvedAt" label="处理时间" width="180" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <template v-if="row.status === 'pending'">
              <el-button size="small" type="success" @click="handleApprove(row)">通过</el-button>
              <el-button size="small" type="danger" @click="handleReject(row)">拒绝</el-button>
            </template>
            <template v-else>
              <el-button size="small" @click="handleView(row)">查看</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="viewDialogVisible" title="审批详情" width="700px">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="审批ID">{{ viewApproval.id }}</el-descriptions-item>
        <el-descriptions-item label="类型">{{ getTypeLabel(viewApproval.type) }}</el-descriptions-item>
        <el-descriptions-item label="标题">{{ viewApproval.title }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusTag(viewApproval.status)">{{ getStatusLabel(viewApproval.status) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="申请人">{{ viewApproval.applicant }}</el-descriptions-item>
        <el-descriptions-item label="申请时间">{{ viewApproval.createdAt }}</el-descriptions-item>
        <el-descriptions-item label="审批人">{{ viewApproval.approver || '-' }}</el-descriptions-item>
        <el-descriptions-item label="处理时间">{{ viewApproval.approvedAt || '-' }}</el-descriptions-item>
        <el-descriptions-item label="备注" :span="2">{{ viewApproval.reason || '-' }}</el-descriptions-item>
      </el-descriptions>
      <div v-if="viewApproval.changes && viewApproval.changes.length > 0" style="margin-top: 20px">
        <h4>变更内容</h4>
        <el-table :data="viewApproval.changes" border>
          <el-table-column prop="field" label="字段" width="150" />
          <el-table-column prop="oldValue" label="原值" />
          <el-table-column prop="newValue" label="新值" />
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

const filterStatus = ref('')

const approvals = ref([
  { id: 'appr-001', type: 'policy_create', title: '创建策略：允许FTP访问', applicant: 'admin', status: 'pending', createdAt: '2024-01-15 10:30:00', approvedAt: '', approver: '', reason: '需要在生产环境开放FTP服务', changes: [{ field: '策略名称', oldValue: '-', newValue: '允许FTP访问' }, { field: '目标节点', oldValue: '-', newValue: '生产节点-01, 生产节点-02' }] },
  { id: 'appr-002', type: 'policy_update', title: '更新策略：允许SSH访问', applicant: 'admin', status: 'pending', createdAt: '2024-01-15 10:15:00', approvedAt: '', approver: '', reason: '扩展SSH源地址范围', changes: [{ field: '源地址', oldValue: '192.168.1.0/24', newValue: '192.168.0.0/16' }] },
  { id: 'appr-003', type: 'node_register', title: '节点注册：开发节点-02', applicant: 'system', status: 'approved', createdAt: '2024-01-14 16:00:00', approvedAt: '2024-01-14 16:30:00', approver: 'admin', reason: '', changes: [] },
  { id: 'appr-004', type: 'policy_delete', title: '删除策略：临时测试规则', applicant: 'testuser', status: 'approved', createdAt: '2024-01-14 10:00:00', approvedAt: '2024-01-14 10:15:00', approver: 'admin', reason: '测试完成，清理规则', changes: [{ field: '策略名称', oldValue: '临时测试规则', newValue: '-' }] },
  { id: 'appr-005', type: 'policy_create', title: '创建策略：开放Redis端口', applicant: 'dev', status: 'rejected', createdAt: '2024-01-13 14:00:00', approvedAt: '2024-01-13 14:30:00', approver: 'admin', reason: '安全风险：Redis端口不应对外暴露', changes: [] }
])

const viewDialogVisible = ref(false)

const viewApproval = reactive({
  id: '',
  type: '',
  title: '',
  applicant: '',
  status: '',
  createdAt: '',
  approvedAt: '',
  approver: '',
  reason: '',
  changes: []
})

const filteredApprovals = computed(() => {
  if (!filterStatus.value) return approvals.value
  return approvals.value.filter(a => a.status === filterStatus.value)
})

const getTypeLabel = (type) => {
  const map = { policy_create: '策略创建', policy_update: '策略更新', policy_delete: '策略删除', node_register: '节点注册' }
  return map[type] || type
}

const getTypeTag = (type) => {
  const map = { policy_create: 'success', policy_update: 'warning', policy_delete: 'danger', node_register: 'info' }
  return map[type] || 'default'
}

const getStatusLabel = (status) => {
  const map = { pending: '待审批', approved: '已通过', rejected: '已拒绝' }
  return map[status] || status
}

const getStatusTag = (status) => {
  const map = { pending: 'warning', approved: 'success', rejected: 'danger' }
  return map[status] || 'default'
}

const handleView = (row) => {
  Object.assign(viewApproval, row)
  viewDialogVisible.value = true
}

const handleApprove = async (row) => {
  try {
    await ElMessageBox.confirm(`确定要通过审批 "${row.title}" 吗？`, '确认通过', { type: 'info' })
    const idx = approvals.value.findIndex(a => a.id === row.id)
    if (idx !== -1) {
      approvals.value[idx].status = 'approved'
      approvals.value[idx].approvedAt = new Date().toLocaleString()
      approvals.value[idx].approver = 'admin'
    }
    ElMessage.success('审批已通过')
  } catch {
    ElMessage.info('已取消')
  }
}

const handleReject = async (row) => {
  try {
    await ElMessageBox.confirm(`确定要拒绝审批 "${row.title}" 吗？`, '确认拒绝', { type: 'warning' })
    const idx = approvals.value.findIndex(a => a.id === row.id)
    if (idx !== -1) {
      approvals.value[idx].status = 'rejected'
      approvals.value[idx].approvedAt = new Date().toLocaleString()
      approvals.value[idx].approver = 'admin'
    }
    ElMessage.success('审批已拒绝')
  } catch {
    ElMessage.info('已取消')
  }
}
</script>

<style scoped>
.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>