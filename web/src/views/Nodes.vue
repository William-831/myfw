<template>
  <div class="nodes-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span class="title">节点管理</span>
          <div class="header-actions">
            <el-popover trigger="click" placement="bottom-end" :width="180">
              <template #reference>
                <el-button size="small">
                  <el-icon><Setting /></el-icon>
                  <span>列设置</span>
                </el-button>
              </template>
              <div class="col-settings">
                <div class="col-settings-title">显示列（取消勾选可收纳）</div>
                <el-checkbox v-for="col in toggleableCols" :key="col.key" v-model="columnVisible[col.key]">{{ col.label }}</el-checkbox>
              </div>
            </el-popover>
            <el-button type="primary" @click="handleAdd">
              <el-icon><Plus /></el-icon>
              添加节点
            </el-button>
          </div>
        </div>
      </template>
      <el-table :data="nodes" style="width: 100%" v-loading="loading" size="default">
        <el-table-column prop="hostname" label="主机名" min-width="140" show-overflow-tooltip />
        <el-table-column label="IP 地址" min-width="130">
          <template #default="{ row }">
            <span v-if="row.ip" class="mono">{{ row.ip }}</span>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
        <el-table-column label="防火墙后端" min-width="110">
          <template #default="{ row }">
            <el-tag :type="getBackendType(row.capability?.selected_backend)" size="small">
              {{ getBackendLabel(row.capability?.selected_backend) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" min-width="90">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">{{ getStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="columnVisible.system" label="系统" min-width="140">
          <template #default="{ row }">
            <span class="small">{{ row.capability?.distro || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column v-if="columnVisible.labels" label="标签" min-width="140">
          <template #default="{ row }">
            <template v-if="parseLabels(row.labels).length > 0">
              <el-tag v-for="tag in parseLabels(row.labels)" :key="tag" size="small" effect="plain" style="margin-right: 4px">{{ tag }}</el-tag>
            </template>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
        <el-table-column v-if="columnVisible.lastSeen" label="最后活跃" min-width="150">
          <template #default="{ row }">
            <span class="small">{{ formatDate(row.last_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-dropdown trigger="click" @command="(cmd) => handleCommand(cmd, row)">
              <el-button size="small">
                操作<el-icon class="el-icon--right"><ArrowDown /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="rules">
                    <el-icon><Connection /></el-icon>查看规则
                  </el-dropdown-item>
                  <el-dropdown-item command="view">详情</el-dropdown-item>
                  <el-dropdown-item command="edit">编辑</el-dropdown-item>
                  <el-dropdown-item command="delete" divided>删除</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
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

    <!-- 节点详情对话框（节点ID 完整显示） -->
    <el-dialog v-model="detailDialogVisible" title="节点详情" width="700px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="节点ID" :span="2">
          <code class="node-id">{{ detailNode.id }}</code>
        </el-descriptions-item>
        <el-descriptions-item label="主机名">{{ detailNode.hostname || '-' }}</el-descriptions-item>
        <el-descriptions-item label="IP 地址">
          <span v-if="detailNode.ip" class="mono">{{ detailNode.ip }}</span>
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

    <!-- iptables 规则对话框（Tab 分类 + 筛选 + 查看完整命令） -->
    <el-dialog v-model="rulesDialogVisible" :title="`iptables 规则 - ${rulesNode.hostname || rulesNode.id}`" width="1080px" top="3vh">
      <div v-loading="rulesLoading">
        <div v-if="!rulesLoading && Object.keys(iptablesRules).length === 0" class="empty-state">
          暂无规则数据。Agent 启动后会自动上报当前 iptables 规则。
        </div>
        <template v-else-if="!rulesLoading">
          <!-- 筛选栏 -->
          <div class="rules-toolbar">
            <el-input v-model="ruleSearch" placeholder="搜索规则内容..." clearable size="small" style="width: 280px">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <el-select v-model="ruleTypeFilter" size="small" style="width: 130px">
              <el-option label="全部类型" value="all" />
              <el-option label="MYFW" value="myfw" />
              <el-option label="系统" value="system" />
            </el-select>
            <el-select v-model="ruleChainFilter" size="small" placeholder="全部链" clearable style="width: 160px">
              <el-option v-for="ch in currentTableChains" :key="ch" :label="ch" :value="ch" />
            </el-select>
            <span class="rule-count">当前表共 {{ filteredRuleCount }} 条</span>
          </div>

          <!-- 按 table 分 Tab -->
          <el-tabs v-model="activeTable" type="card">
            <el-tab-pane v-for="(chains, table) in iptablesRules" :key="table" :name="table">
              <template #label>
                <span>{{ table }}</span>
                <el-badge :value="getTableRuleCount(chains)" type="info" class="tab-badge" />
              </template>
              <div v-for="(rules, chain) in chains" :key="chain" v-show="showChain(chain)" class="rule-chain-section">
                <div class="chain-header">
                  <el-icon><Connection /></el-icon>
                  <span class="chain-name">{{ chain }}</span>
                  <el-tag size="small">{{ filterRules(rules).length }}/{{ rules.length }} 条</el-tag>
                </div>
                <el-table :data="filterRules(rules).map((r, i) => ({ ...r, index: i + 1 }))" size="small" border stripe style="margin-bottom: 12px">
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
                  <el-table-column label="操作" width="110" align="center">
                    <template #default="{ row }">
                      <el-popover trigger="click" :width="440" placement="left">
                        <template #reference>
                          <el-button size="small" link type="primary">查看命令</el-button>
                        </template>
                        <div class="cmd-popover">
                          <div class="cmd-label">完整 iptables 命令（可复制使用）</div>
                          <code class="cmd-code">{{ buildFullCommand(activeTable, row.rule_line) }}</code>
                          <el-button size="small" type="primary" style="margin-top: 8px" @click="copyText(buildFullCommand(activeTable, row.rule_line))">
                            复制命令
                          </el-button>
                        </div>
                      </el-popover>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
              <div v-if="filteredChainCount === 0" class="empty-state">没有匹配的规则</div>
            </el-tab-pane>
          </el-tabs>
        </template>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Connection, Setting, ArrowDown, Search } from '@element-plus/icons-vue'
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

// 列显隐：常用列（主机名/IP/后端/状态/操作）始终显示，非常用列可收纳
const columnVisible = reactive({ system: true, labels: true, lastSeen: true })
const toggleableCols = [
  { key: 'system', label: '系统' },
  { key: 'labels', label: '标签' },
  { key: 'lastSeen', label: '最后活跃' }
]

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
const activeTable = ref('filter')
const ruleSearch = ref('')
const ruleTypeFilter = ref('all')
const ruleChainFilter = ref('')

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

// 规则筛选：按搜索关键字 + 类型过滤
const filterRules = (rules) => {
  return rules.filter(r => {
    if (ruleSearch.value && !r.rule_line.toLowerCase().includes(ruleSearch.value.toLowerCase())) return false
    if (ruleTypeFilter.value === 'myfw' && !r.is_myfw) return false
    if (ruleTypeFilter.value === 'system' && r.is_myfw) return false
    return true
  })
}

// 链筛选：控制整条链是否显示
const showChain = (chain) => {
  if (ruleChainFilter.value && chain !== ruleChainFilter.value) return false
  return true
}

// 当前 table 下所有链名（供链筛选下拉）
const currentTableChains = computed(() => {
  const chains = iptablesRules.value[activeTable.value]
  return chains ? Object.keys(chains) : []
})

// 当前 table 过滤后的规则总数
const filteredRuleCount = computed(() => {
  const chains = iptablesRules.value[activeTable.value]
  if (!chains) return 0
  return Object.entries(chains).reduce((sum, [chain, rules]) => {
    if (ruleChainFilter.value && chain !== ruleChainFilter.value) return sum
    return sum + filterRules(rules).length
  }, 0)
})

// 当前 table 过滤后仍有规则显示的链数
const filteredChainCount = computed(() => {
  const chains = iptablesRules.value[activeTable.value]
  if (!chains) return 0
  return Object.entries(chains).filter(([chain, rules]) =>
    showChain(chain) && filterRules(rules).length > 0
  ).length
})

// 拼接完整 iptables 命令：rule_line 为 iptables-save 格式（-A CHAIN ...）
const buildFullCommand = (table, ruleLine) => {
  return `iptables -t ${table} ${ruleLine}`
}

const copyText = (text) => {
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制到剪贴板')
}

// 操作下拉命令分发
const handleCommand = (cmd, row) => {
  switch (cmd) {
    case 'view': handleView(row); break
    case 'edit': handleEdit(row); break
    case 'rules': handleViewRules(row); break
    case 'delete': handleDelete(row); break
  }
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
  // 重置筛选
  ruleSearch.value = ''
  ruleTypeFilter.value = 'all'
  ruleChainFilter.value = ''
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
    // 默认选中 filter，没有则第一个 table
    const tables = Object.keys(grouped)
    activeTable.value = tables.includes('filter') ? 'filter' : (tables[0] || 'filter')
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
.header-actions { display: flex; gap: 8px; align-items: center; }
.title { font-weight: 600; }
.col-settings { display: flex; flex-direction: column; gap: 6px; }
.col-settings-title { font-size: 12px; color: #909399; margin-bottom: 4px; }
.mono { font-family: 'Courier New', Courier, monospace; }
.node-id { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; word-break: break-all; }
.muted { color: #999; }
.small { font-size: 12px; }

.rules-toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.rule-count { font-size: 12px; color: #909399; margin-left: auto; }
.tab-badge { margin-left: 6px; }
.rule-chain-section { margin-bottom: 16px; }
.chain-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; color: #374151; }
.chain-name { font-weight: 600; }
.rule-code { font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #1f2937; }
.empty-state { text-align: center; padding: 40px; color: #999; }

.cmd-popover { padding: 4px; }
.cmd-label { font-size: 12px; color: #909399; margin-bottom: 8px; }
.cmd-code { display: block; font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; background: #f5f7fa; padding: 10px; border-radius: 4px; word-break: break-all; }
</style>
