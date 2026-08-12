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
        <el-table-column label="节点名称" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.name || row.hostname || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="IP 地址" min-width="150">
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
        <el-table-column label="连接状态" min-width="90">
          <template #default="{ row }">
            <el-tag v-if="row.online" type="success" size="small" effect="dark">在线</el-tag>
            <el-tag v-else type="danger" size="small" effect="dark">离线</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="审批状态" min-width="110">
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
        <el-table-column label="创建时间" min-width="150">
          <template #default="{ row }">
            <span class="small">{{ formatDate(row.created_at) }}</span>
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
                  <el-dropdown-item v-if="row.status === 'PENDING'" command="approve" divided>
                    <el-icon><CircleCheck /></el-icon>审批通过
                  </el-dropdown-item>
                  <el-dropdown-item command="rules">
                    <el-icon><Connection /></el-icon>快速诊断
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
            <li>下载或复制安装脚本到目标 Linux 服务器</li>
            <li>执行 bash install-myfw-agent.sh 完成 Agent 安装</li>
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
        <el-divider content-position="left">Controller 访问配置</el-divider>
        <el-alert type="info" :closable="false" style="margin-bottom: 12px">
          <span style="font-size: 12px">脚本中的 Controller 地址与端口从此处读取，部署到任意服务器填对应值即可，不再绑定固定 IP。</span>
        </el-alert>
        <el-form-item label="访问地址">
          <el-input v-model="addForm.controllerHost" placeholder="Controller 的 IP 或域名（Agent 通过此地址连接）" />
        </el-form-item>
        <el-form-item label="下载端口">
          <el-input v-model="addForm.downloadPort" placeholder="Agent/CA 下载端口，默认 8080" />
        </el-form-item>
        <el-form-item label="gRPC端口">
          <el-input v-model="addForm.grpcPort" placeholder="Agent 长连接端口，默认 9090" />
        </el-form-item>
      </el-form>

      <div v-if="installScript" style="margin-top: 20px">
        <el-divider>安装命令</el-divider>
        <el-alert type="success" :closable="false" style="margin-bottom: 10px">
          复制以下命令到目标 Linux 服务器执行即可安装 Agent
        </el-alert>
        <el-input :model-value="installCommand" type="textarea" :rows="12" readonly style="font-family: monospace; word-break: break-all" />
        <div style="margin-top: 10px; display: flex; gap: 8px; align-items: center">
          <el-button type="primary" size="small" @click="copyScript">复制命令</el-button>
          <el-button size="small" @click="downloadScript">下载完整脚本</el-button>
          <span style="font-size: 12px; color: #909399">粘贴到目标服务器终端直接执行</span>
        </div>
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
        <el-form-item label="节点名称" prop="name">
          <el-input v-model="editForm.name" placeholder="例如：生产服务器-01" />
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
        <el-descriptions-item label="节点名称">{{ detailNode.name || detailNode.hostname || '-' }}</el-descriptions-item>
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

      <!-- 规则库版本历史(计划三):普通任务 Apply 成功自动归档,可一键回滚 -->
      <div style="margin-top: 18px">
        <div class="drift-section-title">规则库版本历史(最近 30 份)</div>
        <el-table :data="revisions" size="small" v-loading="revisionsLoading" max-height="260" style="margin-top: 8px">
          <el-table-column label="版本" width="70" align="center">
            <template #default="{ row }">
              <el-tag size="small" type="info">#{{ row.rev_no }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="来源" width="100">
            <template #default="{ row }">
              <el-tag size="small" :type="sourceTagType(row.source)">{{ sourceLabel(row.source) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="note" label="说明" show-overflow-tooltip />
          <el-table-column label="归档时间" width="160">
            <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="90" align="center">
            <template #default="{ row }">
              <el-button size="small" type="danger" plain :loading="rollbackingRev === row.rev_no" @click="handleRollbackRevision(row)">回滚</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="!revisionsLoading && revisions.length === 0" class="empty-state" style="margin-top: 8px">
          暂无版本记录(普通任务 Apply 成功后将自动归档)
        </div>
      </div>
    </el-dialog>

    <!-- 快速诊断对话框（只读：健康状态 + 链统计 + 规则概览） -->
    <el-dialog v-model="rulesDialogVisible" :title="`快速诊断 - ${rulesNode.name || rulesNode.ip || rulesNode.hostname || rulesNode.id}`" width="1080px" top="3vh">
      <div v-loading="rulesLoading">
        <div v-if="!rulesLoading && Object.keys(iptablesRules).length === 0" class="empty-state">
          暂无规则数据。Agent 启动后会自动上报当前 iptables 规则。
        </div>
        <template v-else-if="!rulesLoading">
          <!-- 健康状态 -->
          <div class="health-grid">
            <div v-for="h in healthChecks" :key="h.label" class="health-item" :class="h.ok ? 'health-ok' : 'health-bad'">
              <span class="health-icon">{{ h.ok ? '✓' : '✗' }}</span>
              <div class="health-body">
                <div class="health-label">{{ h.label }}</div>
                <div class="health-detail">{{ h.detail }}</div>
              </div>
            </div>
          </div>

          <!-- 关键链统计 -->
          <div class="chain-stats">
            <div class="stats-title">关键链统计</div>
            <el-table :data="chainStats" size="small" border stripe style="margin-bottom: 12px">
              <el-table-column prop="table" label="表" width="90" />
              <el-table-column prop="chain" label="链" width="180" />
              <el-table-column label="归属" width="90">
                <template #default="{ row }">
                  <el-tag :type="row.is_myfw ? 'success' : 'info'" size="small">{{ row.is_myfw ? 'MYFW' : '系统' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="count" label="规则数" width="90" align="center" />
            </el-table>
          </div>

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
                  <el-table-column label="操作" width="100" align="center">
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
import { Plus, Connection, Setting, ArrowDown, Search, CaretBottom, CircleCheck } from '@element-plus/icons-vue'
import { getNodes, getNode, updateNode, deleteNode, createBootstrapToken, renewNodeCert, getNodeIptablesRules, getNodeDrift, getTasks, approveNode, getNodeRevisions, rollbackRevision } from '@/api'
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
const columnVisible = reactive({ system: true, labels: true, lastSeen: false, certExpiry: true })
const toggleableCols = [
  { key: 'system', label: '系统' },
  { key: 'labels', label: '标签' },
  { key: 'lastSeen', label: '最后活跃' },
  { key: 'certExpiry', label: '证书过期' }
]

// 添加节点表单
const addFormRef = ref(null)
const addForm = reactive({ name: '', description: '', controllerHost: '', downloadPort: '', grpcPort: '' })
const addRules = {
  name: [{ required: true, message: '请输入节点名称', trigger: 'blur' }]
}
const installScript = ref('')
// 单行安装命令: cat heredoc 把完整脚本写入文件再执行,复制粘贴到终端即可
const installCommand = computed(() => {
  if (!installScript.value) return ''
  return `cat << 'MYFWEOF' > install-myfw-agent.sh\n${installScript.value}\nMYFWEOF\nbash install-myfw-agent.sh`
})

// 编辑节点表单
const editFormRef = ref(null)
const editForm = reactive({ id: '', name: '', ip: '', labels: '' })
const editLabelsStr = ref('')
const editRules = {
  name: [{ required: true, message: '请输入节点名称', trigger: 'blur' }]
}

// 节点详情
const detailNode = reactive({
  id: '', name: '', hostname: '', ip: '', status: '', capability: null,
  labels: '', last_seen: '', created_at: '', cert_not_after: '', online: false
})

// 规则库版本档案(计划三)
const revisions = ref([])
const revisionsLoading = ref(false)
const rollbackingRev = ref(null)
const sourceLabel = (s) => ({ apply: '变更归档', manual: '手动', rollback: '回滚前归档' }[s] || s || '-')
const sourceTagType = (s) => ({ apply: 'primary', manual: 'success', rollback: 'warning' }[s] || 'info')

// iptables 规则
const rulesNode = reactive({ id: '', name: '', hostname: '', ip: '', capability: null })
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
  const map = { 'ACTIVE': '已激活', 'PENDING': '待审核', 'OFFLINE': '离线', 'ARCHIVED': '已归档', 'ABNORMAL': '异常' }
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
    case 'approve': handleApprove(row); break
    case 'delete': handleDelete(row); break
  }
}

// 审批通过 PENDING 节点
const handleApprove = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确认通过节点 ${row.name || row.hostname || row.id} 的注册申请?通过后即可管理该节点。`,
      '审批确认',
      { type: 'success', confirmButtonText: '通过', cancelButtonText: '取消' }
    )
    await approveNode(row.id)
    ElMessage.success('已审批通过')
    loadNodes()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '审批失败')
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
  // Controller 访问配置默认值：当前页面地址 + 标准端口，用户可改
  addForm.controllerHost = window.location.hostname
  addForm.downloadPort = window.location.port || '8080'
  addForm.grpcPort = '9090'
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
    const host = addForm.controllerHost || window.location.hostname
    const dlPort = addForm.downloadPort || '8080'
    const grpcPort = addForm.grpcPort || '9090'
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
curl -fsSL http://${host}:${dlPort}/download/agent/linux-amd64 -o /usr/local/bin/myfw-agent
chmod +x /usr/local/bin/myfw-agent

# 3. 下载 CA 证书（mTLS 必需：Controller 用此 CA 签发 Agent 客户端证书）
echo "下载 CA 证书..."
curl -fsSL http://${host}:${dlPort}/download/ca.pem -o /etc/myfw-agent/ca.pem

# 4. 写入配置文件（启用 mTLS：bootstrap 阶段凭 token 换取客户端证书，写入 cert_file/key_file）
cat > /etc/myfw-agent/agent.yaml << 'AGENTEOF'
controller:
  endpoint: ${host}:${grpcPort}
  tls:
    ca_file: /etc/myfw-agent/ca.pem
    cert_file: /etc/myfw-agent/agent.crt
    key_file: /etc/myfw-agent/agent.key
  bootstrap_token: "${token}"
node:
  labels: []
AGENTEOF

# 5. 写入 systemd unit
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

# 6. 启动服务
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

const copyScript = async () => {
  const cmd = installCommand.value
  try {
    await navigator.clipboard.writeText(cmd)
  } catch {
    // 非 HTTPS 环境 fallback: textarea + execCommand
    const ta = document.createElement('textarea')
    ta.value = cmd
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  }
  ElMessage.success('已复制单行安装命令,粘贴到终端直接执行')
}

const downloadScript = () => {
  const blob = new Blob([installScript.value], { type: 'text/x-shellscript' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'install-myfw-agent.sh'
  a.click()
  URL.revokeObjectURL(url)
  ElMessage.success('脚本已下载,scp 到目标服务器执行 bash install-myfw-agent.sh')
}

// 编辑节点
const handleEdit = (row) => {
  editForm.id = row.id
  editForm.name = row.name || row.hostname || ''
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
      name: editForm.name,
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
    loadRevisions(row.id)
  } catch {
    ElMessage.error('获取节点详情失败')
  }
}

// 加载规则库版本历史(计划三)
const loadRevisions = async (nodeId) => {
  revisionsLoading.value = true
  try {
    const data = await getNodeRevisions(nodeId)
    revisions.value = data.revisions || []
  } catch {
    revisions.value = []
  } finally {
    revisionsLoading.value = false
  }
}

// 回滚到指定版本(二次确认)。回滚是临时排障手段:节点规则库整体收敛到历史版本,
// 完成后实例标记未同步,需重新下发收敛。
const handleRollbackRevision = async (rev) => {
  try {
    await ElMessageBox.confirm(
      `回滚到版本 #${rev.rev_no}(${formatDate(rev.created_at)})?` +
        '该操作将把节点规则库整体收敛到历史版本,回滚为临时排障手段,' +
        '完成后实例将标记为未同步,需重新下发收敛。',
      '规则库版本回滚',
      { type: 'warning', confirmButtonText: '确认回滚', cancelButtonText: '取消' }
    )
  } catch {
    return // 用户取消
  }
  rollbackingRev.value = rev.rev_no
  try {
    await rollbackRevision(detailNode.id, rev.rev_no)
    ElMessage.success(`已发起回滚到版本 #${rev.rev_no},请关注任务进度`)
    await loadRevisions(detailNode.id)
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '回滚失败(节点可能离线)')
  } finally {
    rollbackingRev.value = null
  }
}

// 查看 iptables 规则
const handleViewRules = async (row) => {
  rulesNode.id = row.id
  rulesNode.name = row.name || ''
  rulesNode.hostname = row.hostname
  rulesNode.ip = row.ip
  rulesNode.capability = row.capability || null
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

// 健康状态检查（基于上报规则分析）
const healthChecks = computed(() => {
  const checks = []
  const backendOk = rulesNode.capability?.backend_available !== false
  checks.push({
    label: '防火墙后端',
    ok: backendOk,
    detail: backendOk ? (rulesNode.capability?.selected_backend || '可用') : (rulesNode.capability?.backend_reason || '不可用')
  })
  const allRules = []
  Object.values(iptablesRules.value).forEach(chains => {
    Object.entries(chains).forEach(([chain, rules]) => {
      rules.forEach(r => allRules.push({ ...r, chain }))
    })
  })
  const hasMyfw = allRules.some(r => r.is_myfw || (r.chain || '').startsWith('MYFW-'))
  checks.push({
    label: 'MYFW 命名空间',
    ok: hasMyfw,
    detail: hasMyfw ? 'MYFW 链已就位' : '未发现 MYFW 链'
  })
  const systemChains = ['INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING']
  const jumpSet = new Set()
  allRules.forEach(r => {
    if (systemChains.includes(r.chain)) {
      const m = (r.rule_line || '').match(/-j\s+(MYFW-\S+)/)
      if (m) jumpSet.add(m[1])
    }
  })
  checks.push({
    label: '入口 jump',
    ok: jumpSet.size > 0,
    detail: jumpSet.size > 0 ? `已接管 ${jumpSet.size} 条系统链` : '系统链未 jump 到 MYFW'
  })
  const estChains = ['MYFW-INPUT', 'MYFW-FORWARD', 'MYFW-OUTPUT']
  const estOk = estChains.every(ch => {
    for (const table of Object.keys(iptablesRules.value)) {
      const cr = iptablesRules.value[table][ch]
      if (cr && cr.length > 0) return /ESTABLISHED/.test(cr[0].rule_line || '')
    }
    return false
  })
  checks.push({
    label: 'ESTABLISHED 兜底',
    ok: estOk,
    detail: estOk ? '已建立连接放行就位' : '缺少 ESTABLISHED 首条'
  })
  return checks
})

// 关键链统计
const chainStats = computed(() => {
  const stats = []
  Object.entries(iptablesRules.value).forEach(([table, chains]) => {
    Object.entries(chains).forEach(([chain, rules]) => {
      stats.push({ table, chain, count: rules.length, is_myfw: chain.startsWith('MYFW-') })
    })
  })
  return stats
})

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
      `确定续签节点 ${row.name || row.hostname || row.id} 的证书？续签后节点将短暂重连。`,
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
      `确定要删除节点 ${row.name || row.hostname || row.id} 吗？此操作不可恢复。`,
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
.mono { font-family: 'Courier New', Courier, monospace; white-space: nowrap; }
.guard-tag { margin-left: 4px; cursor: pointer; }
.node-id { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; word-break: break-all; }
.backend-cell { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.backend-reason { font-size: 12px; color: #f56c6c; }
.muted { color: #999; }
.small { font-size: 12px; }

/* 健康状态卡片 */
.health-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
.health-item { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 6px; border: 1px solid #e4e7ed; }
.health-item.health-ok { background: #f0f9eb; border-color: #e1f3d8; }
.health-item.health-bad { background: #fef0f0; border-color: #fde2e2; }
.health-icon { font-size: 18px; font-weight: 700; }
.health-ok .health-icon { color: #67c23a; }
.health-bad .health-icon { color: #f56c6c; }
.health-label { font-size: 13px; font-weight: 600; color: #303133; }
.health-detail { font-size: 12px; color: #909399; margin-top: 2px; }
.chain-stats { margin-bottom: 14px; }
.stats-title { font-size: 13px; font-weight: 600; color: var(--c-text-1); margin-bottom: 8px; }

.rules-toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.rule-count { font-size: 12px; color: #909399; margin-left: auto; }
.tab-badge { margin-left: 6px; }
.rule-chain-section { margin-bottom: 16px; }
.chain-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; color: var(--c-text-1); cursor: pointer; user-select: none; }
.chain-header:hover .chain-name { color: #2563eb; }
.chain-toggle { transition: transform 0.2s; }
.chain-toggle.is-collapsed { transform: rotate(-90deg); }
.chain-name { font-weight: 600; }
.rule-code { font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #1f2937; }
.empty-state { text-align: center; padding: 40px; color: #999; }

.cmd-popover { padding: 4px; }
.cmd-label { font-size: 12px; color: #909399; margin-bottom: 8px; }
.cmd-code { display: block; font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #1f2937; background: #f5f7fa; padding: 10px; border-radius: 4px; word-break: break-all; }
.drift-section-title { font-weight: 600; margin-bottom: 8px; color: var(--c-text-1); }
.drift-item { padding: 4px 0; border-bottom: 1px solid #f0f0f0; }
.drift-item code { font-size: 12px; color: #1f2937; }
</style>
