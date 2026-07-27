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
      <el-table :data="nodes" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="节点ID" width="200" show-overflow-tooltip />
        <el-table-column prop="hostname" label="主机名" width="150" />
        <el-table-column label="IP 地址" width="140">
          <template #default="{ row }">
            <span v-if="row.ip" style="font-family: monospace">{{ row.ip }}</span>
            <span v-else style="color: #999">-</span>
          </template>
        </el-table-column>
        <el-table-column label="防火墙后端" width="120">
          <template #default="{ row }">
            <el-tag :type="getBackendType(row.capability?.selected_backend)" size="small">
              {{ getBackendLabel(row.capability?.selected_backend) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">
              {{ getStatusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="系统" width="150">
          <template #default="{ row }">
            <span style="font-size: 12px">{{ row.capability?.distro || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="标签" width="120">
          <template #default="{ row }">
            <template v-if="parseLabels(row.labels).length > 0">
              <el-tag v-for="tag in parseLabels(row.labels)" :key="tag" size="small" style="margin-right: 4px">{{ tag }}</el-tag>
            </template>
            <span v-else style="color: #999">-</span>
          </template>
        </el-table-column>
        <el-table-column label="最后活跃" width="160">
          <template #default="{ row }">
            <span style="font-size: 12px">{{ formatDate(row.last_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="240">
          <template #default="{ row }">
            <el-button size="small" @click="handleView(row)">详情</el-button>
            <el-button size="small" type="warning" @click="handleEdit(row)">编辑</el-button>
            <el-button size="small" type="primary" @click="handleViewRules(row)">查看规则</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加节点对话框 -->
    <el-dialog v-model="addDialogVisible" title="添加新节点" width="650px" :close-on-click-modal="false">
      <el-alert type="info" :closable="false" style="margin-bottom: 20px">
        <template #title>
          <div>添加节点流程：</div>
          <ol style="margin: 5px 0 0 20px; padding: 0; font-size: 13px">
            <li>输入节点名称，点击"生成安装命令"</li>
            <li>复制生成的命令到目标服务器执行</li>
            <li>Agent 会自动注册到本系统</li>
            <li>在节点列表中审核通过后即可管理</li>
          </ol>
        </template>
      </el-alert>

      <el-form :model="addForm" :rules="addRules" ref="addFormRef" label-width="80px">
        <el-form-item label="节点名称" prop="name">
          <el-input v-model="addForm.name" placeholder="例如：生产服务器-01" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="addForm.description" type="textarea" :rows="2" placeholder="可选" />
        </el-form-item>
      </el-form>

      <div v-if="installScript" style="margin-top: 20px">
        <el-divider>安装命令</el-divider>
        <el-alert type="success" :closable="false" style="margin-bottom: 10px">
          复制以下命令到目标 Linux 服务器执行即可安装 Agent
        </el-alert>
        <el-input v-model="installScript" type="textarea" :rows="8" readonly style="font-family: monospace" />
        <el-button type="primary" size="small" style="margin-top: 10px" @click="copyScript">
          复制命令
        </el-button>
      </div>

      <template #footer>
        <el-button @click="addDialogVisible = false">关闭</el-button>
        <el-button v-if="!installScript" type="primary" @click="handleGenerateScript" :loading="generating">
          生成安装命令
        </el-button>
      </template>
    </el-dialog>

    <!-- 编辑节点对话框 -->
    <el-dialog v-model="editDialogVisible" title="编辑节点信息" width="500px" :close-on-click-modal="false">
      <el-form :model="editForm" :rules="editRules" ref="editFormRef" label-width="80px">
        <el-form-item label="节点ID">
          <el-input :model-value="editForm.id" disabled />
        </el-form-item>
        <el-form-item label="IP 地址">
          <el-input :model-value="editForm.ip" disabled />
        </el-form-item>
        <el-form-item label="主机名" prop="hostname">
          <el-input v-model="editForm.hostname" placeholder="例如：prod-server-01" />
        </el-form-item>
        <el-form-item label="标签">
          <el-input v-model="editLabelsStr" placeholder="标签用逗号分隔，例如：prod,web" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSaveEdit" :loading="saving">保存</el-button>
      </template>
    </el-dialog>

    <!-- 节点详情对话框 -->
    <el-dialog v-model="detailDialogVisible" title="节点详情" width="700px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="节点ID" :span="2">
          <code>{{ detailNode.id }}</code>
        </el-descriptions-item>
        <el-descriptions-item label="主机名">{{ detailNode.hostname || '-' }}</el-descriptions-item>
        <el-descriptions-item label="IP 地址">
          <span v-if="detailNode.ip" style="font-family: monospace">{{ detailNode.ip }}</span>
          <span v-else>-</span>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(detailNode.status)" size="small">
            {{ getStatusLabel(detailNode.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="防火墙后端">
          {{ getBackendLabel(detailNode.capability?.selected_backend) }}
        </el-descriptions-item>
        <el-descriptions-item label="iptables版本">
          {{ detailNode.capability?.iptables_version || '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="标签">
          <template v-if="parseLabels(detailNode.labels).length > 0">
            <el-tag v-for="tag in parseLabels(detailNode.labels)" :key="tag" size="small" style="margin-right: 4px">{{ tag }}</el-tag>
          </template>
          <span v-else>-</span>
        </el-descriptions-item>
        <el-descriptions-item label="系统发行版" :span="2">
          {{ detailNode.capability?.distro || '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="内核版本" :span="2">
          {{ detailNode.capability?.kernel_version || '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="Docker">{{ detailNode.capability?.docker_present ? '已安装' : '未安装' }}</el-descriptions-item>
        <el-descriptions-item label="Kubernetes">{{ detailNode.capability?.k8s_present ? '已安装' : '未安装' }}</el-descriptions-item>
        <el-descriptions-item label="最后活跃" :span="2">{{ formatDate(detailNode.last_seen) }}</el-descriptions-item>
        <el-descriptions-item label="创建时间" :span="2">{{ formatDate(detailNode.created_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- iptables 规则对话框 -->
    <el-dialog v-model="rulesDialogVisible" :title="`iptables 规则 - ${rulesNode.hostname || rulesNode.id}`" width="1000px" top="3vh">
      <div v-loading="rulesLoading">
        <div v-if="!rulesLoading && Object.keys(iptablesRules).length === 0" style="text-align: center; padding: 40px; color: #999">
          暂无规则数据。Agent 启动后会自动上报当前 iptables 规则。
        </div>
        <template v-else>
          <div v-for="(chains, table) in iptablesRules" :key="table" class="rule-table-section">
            <div class="rule-table-header">
              <span class="table-name">{{ table }}</span>
              <el-tag size="small" type="info">{{ getTableRuleCount(chains) }} 条规则</el-tag>
            </div>
            <div v-for="(rules, chain) in chains" :key="chain" class="rule-chain-section">
              <div class="chain-header">
                <el-icon><Connection /></el-icon>
                <span class="chain-name">{{ chain }}</span>
                <el-tag size="small">{{ rules.length }} 条</el-tag>
              </div>
              <el-table :data="rules.map((r, i) => ({ ...r, index: i + 1 }))" size="small" border stripe style="margin-bottom: 12px">
                <el-table-column label="#" width="50" align="center">
                  <template #default="{ row }">{{ row.index }}</template>
                </el-table-column>
                <el-table-column label="规则内容" show-overflow-tooltip>
                  <template #default="{ row }">
                    <code class="rule-code">{{ row.rule_line }}</code>
                  </template>
                </el-table-column>
                <el-table-column label="类型" width="80" align="center">
                  <template #default="{ row }">
                    <el-tag :type="row.is_myfw ? 'success' : 'info'" size="small">
                      {{ row.is_myfw ? 'MYFW' : '系统' }}
                    </el-tag>
                  </template>
                </el-table-column>
              </el-table>
            </div>
          </div>
        </template>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Connection } from '@element-plus/icons-vue'
import { getNodes, getNode, updateNode, deleteNode, createBootstrapToken, getNodeIptablesRules } from '@/api'

const loading = ref(false)
const nodes = ref([])
const addDialogVisible = ref(false)
const editDialogVisible = ref(false)
const detailDialogVisible = ref(false)
const rulesDialogVisible = ref(false)
const generating = ref(false)
const saving = ref(false)
const rulesLoading = ref(false)

// 添加节点表单
const addFormRef = ref(null)
const addForm = reactive({ name: '', description: '' })
const addRules = {
  name: [{ required: true, message: '请输入节点名称', trigger: 'blur' }]
}
const installScript = ref('')

// 编辑节点表单
const editFormRef = ref(null)
const editForm = reactive({ id: '', hostname: '', ip: '', labels: '' })
const editLabelsStr = ref('')
const editRules = {
  hostname: [{ required: true, message: '请输入主机名', trigger: 'blur' }]
}

// 节点详情
const detailNode = reactive({
  id: '', hostname: '', ip: '', status: '', capability: null,
  labels: '', last_seen: '', created_at: ''
})

// iptables 规则
const rulesNode = reactive({ id: '', hostname: '' })
const iptablesRules = ref({})

// 工具函数
const getBackendLabel = (backend) => {
  const map = {
    'FIREWALL_BACKEND_IPTABLES_NFT': 'iptables-nft',
    'FIREWALL_BACKEND_IPTABLES_LEGACY': 'iptables-legacy',
    'FIREWALL_BACKEND_NFTABLES': 'nftables'
  }
  return map[backend] || '未知'
}

const getBackendType = (backend) => {
  const map = {
    'FIREWALL_BACKEND_IPTABLES_NFT': 'info',
    'FIREWALL_BACKEND_IPTABLES_LEGACY': 'warning',
    'FIREWALL_BACKEND_NFTABLES': 'success'
  }
  return map[backend] || 'default'
}

const getStatusLabel = (status) => {
  const map = { 'ACTIVE': '在线', 'PENDING': '待审核', 'OFFLINE': '离线', 'ARCHIVED': '已归档' }
  return map[status] || status || '未知'
}

const getStatusType = (status) => {
  const map = { 'ACTIVE': 'success', 'PENDING': 'warning', 'OFFLINE': 'danger', 'ARCHIVED': 'info' }
  return map[status] || 'info'
}

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  try { return new Date(dateStr).toLocaleString() } catch { return dateStr }
}

const parseLabels = (labelsStr) => {
  if (!labelsStr) return []
  try {
    const parsed = JSON.parse(labelsStr)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

const getTableRuleCount = (chains) => {
  return Object.values(chains).reduce((sum, rules) => sum + rules.length, 0)
}

// 加载节点列表
const loadNodes = async () => {
  loading.value = true
  try {
    const data = await getNodes()
    nodes.value = data.nodes || []
  } catch {
    ElMessage.error('加载节点列表失败')
  } finally {
    loading.value = false
  }
}

// 添加节点
const handleAdd = () => {
  addForm.name = ''
  addForm.description = ''
  installScript.value = ''
  addDialogVisible.value = true
}

const handleGenerateScript = async () => {
  if (!addFormRef.value) return
  await addFormRef.value.validate()

  generating.value = true
  try {
    const data = await createBootstrapToken({ note: addForm.name })
    const token = data.token
    const host = window.location.hostname
    installScript.value = `#!/bin/bash
# MYFW Agent 安装脚本
# 节点名称: ${addForm.name}
# 生成时间: ${new Date().toLocaleString()}

set -e

echo "=== MYFW Agent 安装开始 ==="

# 1. 创建目录
mkdir -p /etc/myfw-agent /var/lib/myfw-agent

# 2. 下载 Agent 二进制
echo "下载 Agent..."
curl -fsSL http://${host}:8080/download/agent/linux-amd64 -o /usr/local/bin/myfw-agent
chmod +x /usr/local/bin/myfw-agent

# 3. 写入配置文件
cat > /etc/myfw-agent/agent.yaml << 'AGENTEOF'
controller:
  endpoint: ${host}:9090
  tls:
    disable: true
  bootstrap_token: "${token}"
node:
  labels: []
AGENTEOF

# 4. 写入 systemd unit
cat > /etc/systemd/system/myfw-agent.service << 'SERVICEEOF'
[Unit]
Description=MYFW Agent - 防火墙管理代理
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myfw-agent --config /etc/myfw-agent/agent.yaml
Restart=on-failure
RestartSec=3s
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
SERVICEEOF

# 5. 启动服务
systemctl daemon-reload
systemctl enable --now myfw-agent

echo "=== MYFW Agent 安装完成 ==="
echo "节点将在 Controller 中显示为'待审核'状态"
echo "请在 Web 控制台中审核通过后即可管理"`

    ElMessage.success('安装命令已生成')
  } catch {
    ElMessage.error('生成安装命令失败')
  } finally {
    generating.value = false
  }
}

const copyScript = () => {
  navigator.clipboard.writeText(installScript.value)
  ElMessage.success('已复制到剪贴板')
}

// 编辑节点
const handleEdit = (row) => {
  editForm.id = row.id
  editForm.hostname = row.hostname || ''
  editForm.ip = row.ip || ''
  editForm.labels = row.labels || ''
  editLabelsStr.value = parseLabels(row.labels).join(', ')
  editDialogVisible.value = true
}

const handleSaveEdit = async () => {
  if (!editFormRef.value) return
  await editFormRef.value.validate()

  saving.value = true
  try {
    const labels = editLabelsStr.value.split(',').map(s => s.trim()).filter(Boolean)
    await updateNode(editForm.id, {
      hostname: editForm.hostname,
      labels
    })
    ElMessage.success('更新成功')
    editDialogVisible.value = false
    loadNodes()
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '更新失败')
  } finally {
    saving.value = false
  }
}

// 查看节点详情
const handleView = async (row) => {
  try {
    const data = await getNode(row.id)
    Object.assign(detailNode, data)
    detailDialogVisible.value = true
  } catch {
    ElMessage.error('获取节点详情失败')
  }
}

// 查看 iptables 规则
const handleViewRules = async (row) => {
  rulesNode.id = row.id
  rulesNode.hostname = row.hostname
  rulesLoading.value = true
  rulesDialogVisible.value = true
  try {
    const data = await getNodeIptablesRules(row.id)
    const rules = data.rules || []

    // 按 table_type 和 chain 分组
    const grouped = {}
    for (const rule of rules) {
      const table = rule.table_type || 'filter'
      const chain = rule.chain || 'INPUT'
      if (!grouped[table]) grouped[table] = {}
      if (!grouped[table][chain]) grouped[table][chain] = []
      grouped[table][chain].push(rule)
    }

    iptablesRules.value = grouped
  } catch {
    iptablesRules.value = {}
    ElMessage.error('获取 iptables 规则失败')
  } finally {
    rulesLoading.value = false
  }
}

// 删除节点
const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定要删除节点 ${row.hostname || row.id} 吗？此操作不可恢复。`,
      '确认删除',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }
    )
    await deleteNode(row.id)
    ElMessage.success('节点已删除')
    loadNodes()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error('删除失败')
  }
}

onMounted(loadNodes)
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.rule-table-section { margin-bottom: 20px; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; }
.rule-table-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }
.table-name { font-size: 16px; font-weight: bold; color: #1f2937; }
.rule-chain-section { margin-bottom: 16px; }
.chain-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; color: #374151; }
.chain-name { font-weight: 600; }
.rule-code { font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #1f2937; }
</style>
