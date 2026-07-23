<template>
  <div class="nodes-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>节点管理</span>
          <el-button type="primary" @click="handleAdd">
            <el-icon><Plus /></el-icon>
            添加节点
          </el-button>
        </div>
      </template>
      <el-table :data="nodes" style="width: 100%">
        <el-table-column prop="id" label="节点ID" width="180" />
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="hostname" label="主机名" width="180" />
        <el-table-column prop="backend" label="防火墙后端" width="150">
          <template #default="{ row }">
            <el-tag :type="getBackendType(row.backend)">{{ getBackendLabel(row.backend) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'">
              {{ row.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="lastSeen" label="最后活跃" width="180" />
        <el-table-column prop="ip" label="IP地址" width="150" />
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
            <el-button size="small" @click="handleView(row)">查看</el-button>
            <el-button size="small" type="primary" @click="handleApply(row)">应用策略</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="600px">
      <el-form :model="nodeForm" :rules="rules" ref="nodeFormRef">
        <el-form-item label="名称" prop="name">
          <el-input v-model="nodeForm.name" placeholder="节点名称" />
        </el-form-item>
        <el-form-item label="防火墙后端" prop="backend">
          <el-select v-model="nodeForm.backend" placeholder="选择后端">
            <el-option label="iptables-nft" value="iptables-nft" />
            <el-option label="iptables-legacy" value="iptables-legacy" />
            <el-option label="nftables" value="nftables" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="nodeForm.description" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSubmit">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="viewDialogVisible" title="节点详情" width="700px">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="节点ID">{{ viewNode.id }}</el-descriptions-item>
        <el-descriptions-item label="名称">{{ viewNode.name }}</el-descriptions-item>
        <el-descriptions-item label="主机名">{{ viewNode.hostname }}</el-descriptions-item>
        <el-descriptions-item label="IP地址">{{ viewNode.ip }}</el-descriptions-item>
        <el-descriptions-item label="防火墙后端">{{ getBackendLabel(viewNode.backend) }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="viewNode.status === 'online' ? 'success' : 'danger'">
            {{ viewNode.status === 'online' ? '在线' : '离线' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="最后活跃">{{ viewNode.lastSeen }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ viewNode.createdAt }}</el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">{{ viewNode.description }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'

const nodes = ref([
  { id: 'node-001', name: '生产节点-01', hostname: 'prod-server-01', backend: 'iptables-nft', status: 'online', lastSeen: '2024-01-15 10:30:00', ip: '192.168.1.10', description: '生产环境防火墙节点' },
  { id: 'node-002', name: '生产节点-02', hostname: 'prod-server-02', backend: 'nftables', status: 'online', lastSeen: '2024-01-15 10:28:00', ip: '192.168.1.11', description: '生产环境防火墙节点' },
  { id: 'node-003', name: '测试节点-01', hostname: 'test-server-01', backend: 'iptables-legacy', status: 'online', lastSeen: '2024-01-15 10:25:00', ip: '192.168.2.10', description: '测试环境防火墙节点' },
  { id: 'node-004', name: '开发节点-01', hostname: 'dev-server-01', backend: 'nftables', status: 'offline', lastSeen: '2024-01-14 18:00:00', ip: '192.168.3.10', description: '开发环境防火墙节点' },
  { id: 'node-005', name: '监控节点-01', hostname: 'monitor-server-01', backend: 'iptables-nft', status: 'online', lastSeen: '2024-01-15 10:30:00', ip: '192.168.4.10', description: '监控系统防火墙节点' }
])

const dialogVisible = ref(false)
const viewDialogVisible = ref(false)
const isEdit = ref(false)
const nodeFormRef = ref(null)

const nodeForm = reactive({
  name: '',
  backend: '',
  description: ''
})

const viewNode = reactive({
  id: '',
  name: '',
  hostname: '',
  backend: '',
  status: '',
  lastSeen: '',
  ip: '',
  createdAt: '',
  description: ''
})

const rules = {
  name: [{ required: true, message: '请输入节点名称', trigger: 'blur' }],
  backend: [{ required: true, message: '请选择防火墙后端', trigger: 'change' }]
}

const getBackendLabel = (backend) => {
  const map = { 'iptables-nft': 'iptables-nft', 'iptables-legacy': 'iptables-legacy', 'nftables': 'nftables' }
  return map[backend] || backend
}

const getBackendType = (backend) => {
  const map = { 'iptables-nft': 'info', 'iptables-legacy': 'warning', 'nftables': 'success' }
  return map[backend] || 'default'
}

const dialogTitle = () => isEdit.value ? '编辑节点' : '添加节点'

const handleAdd = () => {
  isEdit.value = false
  Object.assign(nodeForm, { name: '', backend: '', description: '' })
  dialogVisible.value = true
}

const handleView = (row) => {
  Object.assign(viewNode, row)
  viewDialogVisible.value = true
}

const handleApply = (row) => {
  ElMessage.info(`正在向节点 ${row.name} 应用策略...`)
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(`确定要删除节点 ${row.name} 吗？`, '确认删除', { type: 'warning' })
    nodes.value = nodes.value.filter(n => n.id !== row.id)
    ElMessage.success('删除成功')
  } catch {
    ElMessage.info('已取消删除')
  }
}

const handleSubmit = () => {
  if (!nodeFormRef.value || !nodeFormRef.value.validate()) return
  if (isEdit.value) {
    ElMessage.success('更新成功')
  } else {
    nodes.value.unshift({
      id: `node-${String(Date.now()).slice(-3)}`,
      name: nodeForm.name,
      hostname: nodeForm.name.toLowerCase().replace(/\s/g, '-'),
      backend: nodeForm.backend,
      status: 'offline',
      lastSeen: '-',
      ip: '-',
      createdAt: new Date().toLocaleString(),
      description: nodeForm.description
    })
    ElMessage.success('添加成功')
  }
  dialogVisible.value = false
}
</script>

<style scoped>
.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>