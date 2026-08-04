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
        <el-table-column label="状态" min-width="110">
          <template #default="{ row }">
            <el-tooltip
              v-if="row.status === 'ABNORMAL' && row.capability?.backend_reason"
              :content="'后端不可用：' + row.capability.backend_reason"
              placement="top"
            >
              <el-tag :type="getStatusType(row.status)" size="small" effect="dark">{{ getStatusLabel(row.status) }}</el-tag>
            </el-tooltip>
            <el-tag v-else :type="getStatusType(row.status)" size="small">{{ getStatusLabel(row.status) }}</el-tag>
            <el-tag v-if="hasGuard(row.id)" type="warning" size="small" effect="dark" class="guard-tag" @click="guard.open()">待确认</el-tag>
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
        <el-table-column v-if="columnVisible.certExpiry" label="证书过期" min-width="170">
          <template #default="{ row }">
            <template v-if="row.cert_not_after">
              <div class="small">{{ formatDate(row.cert_not_after) }}</div>
              <el-tag :type="certExpiryInfo(row.cert_not_after).type" size="small" effect="dark">
                {{ certExpiryInfo(row.cert_not_after).text }}
              </el-tag>
            </template>
            <span v-else class="muted">-</span>
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
                  <el-dropdown-item command="renew" divided>续签证书</el-dropdown-item>
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
          <div class="backend-cell">
            <el-tag :type="getBackendType(detailNode.capability?.selected_backend)" size="small">
              {{ getBackendLabel(detailNode.capability?.selected_backend) }}
            </el-tag>
            <el-tag
              v-if="detailNode.capability?.backend_available === false"
              type="danger"
              size="small"
              effect="dark"
            >后端服务不可用</el-tag>
            <span
              v-if="detailNode.capability?.backend_available === false && detailNode.capability?.backend_reason"
              class="backend-reason"
            >{{ detailNode.capability.backend_reason }}</span>
          </div>
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
        <el-descriptions-item label="证书过期" :span="2">
          <template v-if="detailNode.cert_not_after">
            <span class="small">{{ formatDate(detailNode.cert_not_after) }}</span>
            <el-tag :type="certExpiryInfo(detailNode.cert_not_after).type" size="small" effect="dark" style="margin-left: 8px">
              {{ certExpiryInfo(detailNode.cert_not_after).text }}
            </el-tag>
          </template>
          <span v-else>-</span>
        </el-descriptions-item>
        <el-descriptions-item label="最后活跃" :span="2">{{ formatDate(detailNode.last_seen) }}</el-descriptions-item>
        <el-descriptions-item label="创建时间" :span="2">{{ formatDate(detailNode.created_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- iptables 规则对话框（Tab 分类 + 筛选 + 查看完整命令） -->
    <el-dialog v-model="rulesDialogVisible" :title="`iptables 规则 - ${rulesNode.ip || rulesNode.hostname || rulesNode.id}`" width="1080px" top="3vh">
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
            <el-button type="primary" size="small" @click="handleAddRule">
              <el-icon><Plus /></el-icon>添加规则
            </el-button>
            <el-button size="small" @click="handleCheckDrift" :loading="driftLoading">合规检查</el-button>
          </div>

          <!-- 按 table 分 Tab -->
          <el-tabs v-model="activeTable" type="card">
            <el-tab-pane v-for="(chains, table) in iptablesRules" :key="table" :name="table">
              <template #label>
                <span>{{ table }}</span>
                <el-badge :value="getTableRuleCount(chains)" type="info" class="tab-badge" />
              </template>
              <div v-for="(rules, chain) in chains" :key="chain" v-show="showChain(chain)" class="rule-chain-section">
                <div class="chain-header" @click="toggleChain(table, chain)">
                  <el-icon class="chain-toggle" :class="{ 'is-collapsed': isChainCollapsed(table, chain) }"><CaretBottom /></el-icon>
                  <el-icon><Connection /></el-icon>
                  <span class="chain-name">{{ chain }}</span>
                  <el-tag size="small">{{ filterRules(rules).length }}/{{ rules.length }} 条</el-tag>
                </div>
                <el-table v-show="!isChainCollapsed(table, chain)" :data="filterRules(rules).map((r, i) => ({ ...r, index: i + 1 }))" size="small" border stripe style="margin-bottom: 12px">
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
                  <el-table-column label="操作" width="210" align="center">
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
                      <el-button size="small" link type="warning" @click="handleEditRule(row)">编辑</el-button>
                      <el-button size="small" link type="danger" @click="handleDeleteRule(row)">删除</el-button>
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

    <!-- 规则操作对话框（增删改插，双模式） -->
    <el-dialog v-model="ruleOpDialogVisible" :title="ruleOpTitle" width="620px" :close-on-click-modal="false">
      <el-form :model="ruleOpForm" label-width="90px" v-if="ruleOpForm.op !== 'delete'">
        <el-form-item label="表">
          <el-select v-model="ruleOpForm.table" style="width: 160px">
            <el-option label="filter" value="filter" />
            <el-option label="nat" value="nat" />
            <el-option label="mangle" value="mangle" />
            <el-option label="raw" value="raw" />
          </el-select>
        </el-form-item>
        <el-form-item label="链">
          <el-select v-model="ruleOpForm.chain" filterable allow-create default-first-option style="width: 200px" placeholder="如 MYFW-INPUT">
            <el-option v-for="ch in chainOptions" :key="ch" :label="ch" :value="ch" />
          </el-select>
        </el-form-item>
        <el-form-item label="模式">
          <el-radio-group v-model="ruleOpMode">
            <el-radio value="structured">结构化</el-radio>
            <el-radio value="expert">专家模式</el-radio>
          </el-radio-group>
        </el-form-item>
        <template v-if="ruleOpMode === 'structured'">
          <el-form-item label="动作">
            <el-select v-model="ruleOpForm.action" style="width: 160px">
              <el-option label="ACCEPT" value="ACCEPT" />
              <el-option label="DROP" value="DROP" />
              <el-option label="REJECT" value="REJECT" />
              <el-option label="MARK" value="MARK" />
            </el-select>
          </el-form-item>
          <el-form-item label="协议">
            <el-select v-model="ruleOpForm.protocol" style="width: 160px">
              <el-option label="任意" value="any" />
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="ICMP" value="icmp" />
            </el-select>
          </el-form-item>
          <el-form-item label="源地址"><el-input v-model="ruleOpForm.source" placeholder="IP/CIDR，可空" /></el-form-item>
          <el-form-item label="目的地址"><el-input v-model="ruleOpForm.destination" placeholder="IP/CIDR，可空" /></el-form-item>
          <el-form-item label="端口"><el-input v-model="ruleOpForm.port" placeholder="如 80 或 1000:2000" /></el-form-item>
        </template>
        <template v-else>
          <el-form-item label="规则体">
            <el-input v-model="ruleOpForm.rule_line" type="textarea" :rows="2" placeholder="-p tcp --dport 80 -j ACCEPT" />
          </el-form-item>
        </template>
        <el-form-item v-if="ruleOpForm.op === 'insert'" label="插入位置">
          <el-input-number v-model="ruleOpForm.position" :min="1" />
        </el-form-item>
      </el-form>
      <el-alert v-else type="warning" :closable="false" style="margin-bottom: 12px">
        确认删除以下规则？
      </el-alert>
      <div v-if="ruleOpForm.op === 'delete'">
        <code class="rule-code">{{ ruleOpForm.rule_line }}</code>
      </div>
      <template #footer>
        <el-button @click="ruleOpDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="submitRuleOp" :loading="ruleOpSaving">执行</el-button>
      </template>
    </el-dialog>

    <!-- 合规检查对话框（策略漂移检测） -->
    <el-dialog v-model="driftDialogVisible" title="策略合规检查" width="760px">
      <div v-loading="driftLoading">
        <el-alert :type="driftResult.drifted ? 'error' : 'success'" :closable="false" style="margin-bottom: 12px">
          {{ driftResult.drifted ? `检测到漂移：期望 ${driftResult.expected_count} 条，实际 ${driftResult.actual_count} 条` : `合规：期望 ${driftResult.expected_count} 条，实际 ${driftResult.actual_count} 条` }}
        </el-alert>
        <el-row :gutter="16">
          <el-col :span="12">
            <div class="drift-section-title">策略期望规则（{{ driftResult.expected_count }}）</div>
            <div v-for="r in driftResult.expected" :key="r.id" class="drift-item">
              <code>{{ r.id }}: {{ r.protocol }} {{ r.port_range }} -&gt; {{ r.action }}</code>
            </div>
          </el-col>
          <el-col :span="12">
            <div class="drift-section-title">节点真实 MYFW 规则（{{ driftResult.actual_count }}）</div>
            <div v-for="r in driftResult.actual" :key="r.id" class="drift-item">
              <code>{{ r.rule_line }}</code>
            </div>
          </el-col>
        </el-row>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Connection, Setting, ArrowDown, Search, CaretBottom } from '@element-plus/icons-vue'
import { getNodes, getNode, updateNode, deleteNode, createBootstrapToken, renewNodeCert, getNodeIptablesRules, operateNodeRule, getNodeDrift, getTasks } from '@/api'
import { useGuardStore } from '@/stores/guard'

const loading = ref(false)
const nodes = ref([])
const guard = useGuardStore()
const guardNodeIds = ref(new Set())
const hasGuard = (nodeId) => guardNodeIds.value.has(nodeId)
const loadGuardTasks = async () => {
  try {
    const data = await getTasks({ status: 'confirm_wait' })
    guardNodeIds.value = new Set((data.tasks || []).map((t) => t.node_id))
  } catch {
    // 保护期任务加载失败不影响节点列表展示
  }
}
const addDialogVisible = ref(false)
const editDialogVisible = ref(false)
const detailDialogVisible = ref(false)
const rulesDialogVisible = ref(false)
const generating = ref(false)
const saving = ref(false)
const rulesLoading = ref(false)

// 列显隐：常用列（主机名/IP/后端/状态/操作）始终显示，非常用列可收纳
const columnVisible = reactive({ system: true, labels: true, lastSeen: true, certExpiry: true })
const toggleableCols = [
  { key: 'system', label: '系统' },
  { key: 'labels', label: '标签' },
  { key: 'lastSeen', label: '最后活跃' },
  { key: 'certExpiry', label: '证书过期' }
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
  labels: '', last_seen: '', created_at: '', cert_not_after: ''
})

// iptables 规则
const rulesNode = reactive({ id: '', hostname: '', ip: '' })
const iptablesRules = ref({})
const activeTable = ref('filter')
const ruleSearch = ref('')
const ruleTypeFilter = ref('all')
const ruleChainFilter = ref('')

// 链折叠状态:key = `${table}:${chain}`,点击链头切换展开/收起
const collapsedChains = reactive({})
const toggleChain = (table, chain) => {
  const key = `${table}:${chain}`
  collapsedChains[key] = !collapsedChains[key]
}
const isChainCollapsed = (table, chain) => !!collapsedChains[`${table}:${chain}`]

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
  const map = { 'ACTIVE': '在线', 'PENDING': '待审核', 'OFFLINE': '离线', 'ARCHIVED': '已归档', 'ABNORMAL': '异常' }
  return map[status] || status || '未知'
}

const getStatusType = (status) => {
  const map = { 'ACTIVE': 'success', 'PENDING': 'warning', 'OFFLINE': 'danger', 'ARCHIVED': 'info', 'ABNORMAL': 'danger' }
  return map[status] || 'info'
}

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  try { return new Date(dateStr).toLocaleString() } catch { return dateStr }
}

// 证书过期信息：返回 el-tag 类型与文案（已过期/<24h 红，<7天 橙，否则绿）
const certExpiryInfo = (notAfter) => {
  if (!notAfter) return null
  const remain = new Date(notAfter).getTime() - Date.now()
  if (remain <= 0) return { type: 'danger', text: '已过期' }
  const hours = remain / 3600000
  if (hours < 24) return { type: 'danger', text: `${Math.ceil(hours)} 小时后过期` }
  const days = hours / 24
  if (days < 7) return { type: 'warning', text: `${Math.ceil(days)} 天后过期` }
  return { type: 'success', text: `${Math.ceil(days)} 天后过期` }
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
    case 'renew': handleRenew(row); break
    case 'delete': handleDelete(row); break
  }
}

// 加载节点列表
const loadNodes = async () => {
  loading.value = true
  try {
    const data = await getNodes()
    nodes.value = data.nodes || []
    loadGuardTasks()
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
  rulesNode.ip = row.ip
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

// 规则操作（增删改插，双模式）
const ruleOpDialogVisible = ref(false)
const ruleOpSaving = ref(false)
const ruleOpMode = ref('structured')
const ruleOpTitle = ref('')
const ruleOpForm = reactive({
  op: 'add', table: 'filter', chain: 'MYFW-INPUT', position: 1,
  rule_line: '', action: 'ACCEPT', protocol: 'tcp',
  source: '', destination: '', port: ''
})

// 各表 MYFW 托管链,用于链下拉选项(节点级直操作只允许 MYFW-*,内置链由平台 jump 接管)
const CHAINS_BY_TABLE = {
  filter: ['MYFW-INPUT', 'MYFW-OUTPUT', 'MYFW-FORWARD'],
  nat: ['MYFW-PREROUTING', 'MYFW-POSTROUTING'],
  mangle: ['MYFW-MANGLE'],
  raw: []
}
const chainOptions = computed(() => CHAINS_BY_TABLE[ruleOpForm.table] || [])

const handleAddRule = () => {
  ruleOpTitle.value = '添加规则'
  ruleOpMode.value = 'structured'
  ruleOpForm.op = 'add'
  ruleOpForm.table = activeTable.value || 'filter'
  ruleOpForm.chain = 'MYFW-INPUT'
  ruleOpForm.position = 1
  ruleOpForm.rule_line = ''
  ruleOpForm.action = 'ACCEPT'
  ruleOpForm.protocol = 'tcp'
  ruleOpForm.source = ''
  ruleOpForm.destination = ''
  ruleOpForm.port = ''
  ruleOpDialogVisible.value = true
}

const handleEditRule = (row) => {
  ruleOpTitle.value = '编辑规则（替换）'
  ruleOpMode.value = 'expert'
  ruleOpForm.op = 'replace'
  ruleOpForm.table = activeTable.value || row.table_type || 'filter'
  ruleOpForm.chain = row.chain || 'MYFW-INPUT'
  ruleOpForm.position = row.index || 1
  ruleOpForm.rule_line = row.rule_line || ''
  ruleOpDialogVisible.value = true
}

const handleDeleteRule = (row) => {
  ruleOpTitle.value = '删除规则'
  ruleOpForm.op = 'delete'
  ruleOpForm.table = activeTable.value || row.table_type || 'filter'
  ruleOpForm.chain = row.chain || 'MYFW-INPUT'
  ruleOpForm.position = row.index || 1
  ruleOpForm.rule_line = row.rule_line || ''
  ruleOpDialogVisible.value = true
}

const submitRuleOp = async () => {
  const opMap = { add: 1, insert: 2, delete: 3, replace: 4 }
  const op = {
    table: ruleOpForm.table,
    chain: ruleOpForm.chain,
    op: opMap[ruleOpForm.op] || 0,
    position: ruleOpForm.position || 0,
    rule_line: ruleOpForm.op === 'delete' ? ruleOpForm.rule_line : (ruleOpMode.value === 'expert' ? ruleOpForm.rule_line : ''),
    action: ruleOpForm.action,
    protocol: ruleOpForm.protocol,
    source: ruleOpForm.source,
    destination: ruleOpForm.destination,
    port: ruleOpForm.port,
  }
  ruleOpSaving.value = true
  try {
    const data = await operateNodeRule(rulesNode.id, op)
    if (data.result?.ok) {
      ElMessage.success('操作成功：' + (data.result.message || ''))
      ruleOpDialogVisible.value = false
      // 刷新规则列表（实时拉取最新状态）
      await handleViewRules({ id: rulesNode.id, hostname: rulesNode.hostname })
    } else {
      ElMessage.error(data.result?.message || '操作失败')
    }
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '操作失败')
  } finally {
    ruleOpSaving.value = false
  }
}

// 合规检查（策略漂移检测）
const driftDialogVisible = ref(false)
const driftLoading = ref(false)
const driftResult = reactive({ expected: [], actual: [], expected_count: 0, actual_count: 0, drifted: false })

const handleCheckDrift = async () => {
  driftLoading.value = true
  driftDialogVisible.value = true
  try {
    const data = await getNodeDrift(rulesNode.id)
    Object.assign(driftResult, data)
  } catch {
    ElMessage.error('合规检查失败')
  } finally {
    driftLoading.value = false
  }
}

// 续签证书
const handleRenew = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定续签节点 ${row.hostname || row.id} 的证书？续签后节点将短暂重连。`,
      '续签证书',
      { type: 'warning', confirmButtonText: '续签', cancelButtonText: '取消' }
    )
    await renewNodeCert(row.id)
    ElMessage.success('续签指令已下发，节点将重连加载新证书')
    setTimeout(loadNodes, 3000)
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '续签失败')
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
.guard-tag { margin-left: 4px; cursor: pointer; }
.node-id { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; word-break: break-all; }
.backend-cell { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.backend-reason { font-size: 12px; color: #f56c6c; }
.muted { color: #999; }
.small { font-size: 12px; }

.rules-toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.rule-count { font-size: 12px; color: #909399; margin-left: auto; }
.tab-badge { margin-left: 6px; }
.rule-chain-section { margin-bottom: 16px; }
.chain-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; color: #374151; cursor: pointer; user-select: none; }
.chain-header:hover .chain-name { color: #2563eb; }
.chain-toggle { transition: transform 0.2s; }
.chain-toggle.is-collapsed { transform: rotate(-90deg); }
.chain-name { font-weight: 600; }
.rule-code { font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #1f2937; }
.empty-state { text-align: center; padding: 40px; color: #999; }

.cmd-popover { padding: 4px; }
.cmd-label { font-size: 12px; color: #909399; margin-bottom: 8px; }
.cmd-code { display: block; font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; background: #f5f7fa; padding: 10px; border-radius: 4px; word-break: break-all; }
.drift-section-title { font-weight: 600; margin-bottom: 8px; color: #374151; }
.drift-item { padding: 4px 0; border-bottom: 1px solid #f0f0f0; }
.drift-item code { font-size: 12px; color: #1f2937; }
</style>
