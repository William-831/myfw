<template>
  <div class="policies-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">策略管理</h2>
        <el-tag size="small" type="info">{{ filteredPolicies.length }} 条策略</el-tag>
      </div>
      <div class="header-right">
        <el-switch
          v-model="expertMode"
          active-text="专家模式"
          inactive-text="简易模式"
          class="mode-switch"
        />
      </div>
    </div>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <el-input
        v-model="searchKeyword"
        placeholder="搜索策略名称、源地址、目标地址..."
        clearable
        style="width: 300px"
        @input="handleSearch"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-select v-model="filterDirection" placeholder="方向" clearable style="width: 120px" @change="handleSearch">
        <el-option label="入站" value="INBOUND" />
        <el-option label="出站" value="OUTBOUND" />
        <el-option label="转发" value="FORWARD" />
      </el-select>
      <el-select v-model="filterAction" placeholder="动作" clearable style="width: 120px" @change="handleSearch">
        <el-option label="允许" value="ACCEPT" />
        <el-option label="丢弃" value="DROP" />
        <el-option label="拒绝" value="REJECT" />
      </el-select>
      <el-select v-model="filterEnabled" placeholder="状态" clearable style="width: 120px" @change="handleSearch">
        <el-option label="已启用" :value="true" />
        <el-option label="已禁用" :value="false" />
      </el-select>
      <!-- 主机筛选 -->
      <el-popover placement="bottom" :width="400" trigger="click">
        <template #reference>
          <el-button :type="selectedHosts.length ? 'primary' : 'default'">
            <el-icon><Connection /></el-icon>
            按主机筛选
            <el-badge v-if="selectedHosts.length" :value="selectedHosts.length" class="host-badge" />
          </el-button>
        </template>
        <div class="host-filter-panel">
          <el-input v-model="hostSearch" placeholder="搜索主机..." clearable size="small" style="margin-bottom: 12px" />
          <div class="host-list">
            <el-checkbox
              v-for="node in filteredHosts"
              :key="node.id"
              v-model="node._selected"
              @change="onHostSelectionChange"
            >
              <span class="host-item">
                <span class="host-name">{{ node.hostname || node.id }}</span>
                <el-tag :type="node.status === 'ACTIVE' ? 'success' : 'info'" size="small">
                  {{ node.status === 'ACTIVE' ? '在线' : '离线' }}
                </el-tag>
                <span class="host-ip">{{ node.ip || '-' }}</span>
              </span>
            </el-checkbox>
          </div>
          <div class="host-actions">
            <el-button size="small" @click="selectAllHosts">全选</el-button>
            <el-button size="small" @click="clearHosts">清除</el-button>
            <span class="host-count">已选 {{ selectedHosts.length }} 台</span>
          </div>
        </div>
      </el-popover>
      <el-button @click="resetSearch">重置</el-button>
    </div>

    <!-- 批量操作栏 -->
    <div v-if="selectedIds.length > 0" class="batch-bar">
      <span class="batch-count">已选 {{ selectedIds.length }} 条</span>
      <el-button size="small" type="success" @click="handleBatchToggle(true)">批量启用</el-button>
      <el-button size="small" type="warning" @click="handleBatchToggle(false)">批量禁用</el-button>
      <el-button size="small" type="danger" @click="handleBatchDelete">批量删除</el-button>
      <el-button size="small" type="primary" @click="showBatchApplyDialog">批量应用到主机</el-button>
    </div>

    <!-- 操作按钮栏 -->
    <div class="action-bar">
      <el-button type="primary" @click="openAddDialog">
        <el-icon><Plus /></el-icon>
        新增策略
      </el-button>
      <el-button @click="handleApplyAll" :loading="applyingAll">
        <el-icon><Refresh /></el-icon>
        全量应用
      </el-button>
      <el-button @click="detectPolicyConflicts" :loading="checkingConflicts">
        <el-icon><Warning /></el-icon>
        检测冲突
      </el-button>
    </div>

    <!-- 冲突提示 -->
    <div v-if="conflicts.length > 0" class="conflicts-section">
      <el-alert
        title="检测到策略冲突"
        type="warning"
        :closable="true"
        @close="conflicts = []"
      >
        <template #default>
          <div v-for="(c, idx) in conflicts" :key="idx" class="conflict-item">
            <el-tag :type="c.severity === 'error' ? 'danger' : c.severity === 'warning' ? 'warning' : 'info'" size="small">
              {{ c.type === 'priority_overlap' ? '优先级重叠' : c.type === 'action_conflict' ? '动作矛盾' : '规则冗余' }}
            </el-tag>
            <span>策略 #{{ c.policy_a }} 与 #{{ c.policy_b }}: {{ c.message }}</span>
          </div>
        </template>
      </el-alert>
    </div>

    <!-- 简易模式: 云安全组风格列表 -->
    <div v-if="!expertMode" class="simple-mode">
      <div v-if="filteredPolicies.length === 0" class="empty-state">
        <el-empty description="暂无策略" />
      </div>
      <div v-else class="policy-list">
        <div
          v-for="(policy, idx) in filteredPolicies"
          :key="policy.id"
          class="policy-row"
          :class="{ disabled: !policy.enabled, selected: selectedIds.includes(policy.id) }"
        >
          <!-- 优先级色条 -->
          <div class="priority-bar" :class="getPriorityClass(policy.priority)" />

          <!-- 行头 -->
          <div class="row-header">
            <el-checkbox
              :model-value="selectedIds.includes(policy.id)"
              @change="toggleSelect(policy.id)"
            />
            <span class="priority-badge">#{{ policy.priority }}</span>
            <span class="policy-name">{{ policy.name }}</span>
            <el-tag :type="policy.enabled ? 'success' : 'info'" size="small">
              {{ policy.enabled ? '已启用' : '已禁用' }}
            </el-tag>
            <div class="row-actions">
              <el-button size="small" text @click="viewPolicy(policy)">查看</el-button>
              <el-button size="small" text type="warning" @click="editPolicy(policy)">编辑</el-button>
              <el-button size="small" text type="danger" @click="handleDelete(policy)">删除</el-button>
              <el-button size="small" text type="primary" @click="handleApply(policy)" :loading="policy._applying">应用</el-button>
              <el-button size="small" text type="info" @click="viewVersions(policy)">版本</el-button>
            </div>
          </div>

          <!-- 规则摘要 -->
          <div class="rule-summary">
            <span class="direction-tag" :class="policy.direction ? policy.direction.toLowerCase() : ''">
              {{ getDirectionIcon(policy.direction) }} {{ getDirectionLabel(policy.direction) }}
            </span>
            <span class="field">
              <span class="field-label">源</span>
              <span class="field-value mono">{{ policy.source || '任意' }}</span>
            </span>
            <span class="field">
              <span class="field-label">目的</span>
              <span class="field-value mono">{{ policy.destination || '任意' }}</span>
            </span>
            <span class="field">
              <span class="field-label">协议</span>
              <span class="field-value">{{ policy.protocol || 'ANY' }}</span>
            </span>
            <span class="field">
              <span class="field-label">端口</span>
              <span class="field-value mono">{{ policy.port_range || '任意' }}</span>
            </span>
            <span class="action-tag" :class="policy.action ? policy.action.toLowerCase() : ''">
              {{ getActionIcon(policy.action) }} {{ getActionLabel(policy.action) }}
            </span>
          </div>

          <!-- 关联信息 -->
          <div class="relation-info">
            <span v-if="getPolicyTargets(policy).length > 0" class="targets">
              <el-icon><Connection /></el-icon>
              关联主机:
              <el-tooltip
                v-for="nodeId in getPolicyTargets(policy)"
                :key="nodeId"
                :content="nodeId"
                placement="top"
              >
                <el-tag size="small" type="info" class="target-tag">
                  <span class="target-ip">{{ getNodeDisplay(nodeId).ip || getNodeDisplay(nodeId).hostname || nodeId.slice(0, 12) }}</span>
                  <span v-if="getNodeDisplay(nodeId).hostname && getNodeDisplay(nodeId).ip" class="target-host">{{ getNodeDisplay(nodeId).hostname }}</span>
                </el-tag>
              </el-tooltip>
            </span>
            <span v-if="policy.description" class="desc">{{ policy.description }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 专家模式: 链结构树 -->
    <div v-else class="expert-mode">
      <div class="expert-header">
        <span>选择主机查看链结构:</span>
        <el-select v-model="selectedExpertNode" placeholder="选择主机" style="width: 300px" @change="loadChainTree">
          <el-option
            v-for="node in allNodes"
            :key="node.id"
            :label="`${node.hostname || node.id} (${node.ip || '无IP'})`"
            :value="node.id"
          />
        </el-select>
        <el-button @click="loadChainTree" :loading="chainTreeLoading" :disabled="!selectedExpertNode">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>

      <div v-if="chainTreeLoading" class="loading-state">
        <el-skeleton :rows="5" animated />
      </div>

      <div v-else-if="!selectedExpertNode" class="empty-state">
        <el-empty description="请选择一台主机查看 iptables 链结构" />
      </div>

      <div v-else-if="chainTree.tables && chainTree.tables.length > 0" class="chain-tree">
        <div v-for="table in chainTree.tables" :key="table.name" class="table-section">
          <div class="table-header">
            <h3 class="table-title">{{ table.name }} 表</h3>
          </div>

          <div v-for="chain in table.chains" :key="chain.name" class="chain-block" :class="{ 'is-myfw': chain.is_myfw }">
            <div class="chain-node" :class="{ 'system-chain': !chain.is_myfw, 'myfw-chain': chain.is_myfw }">
              <span class="chain-icon">{{ chain.is_myfw ? '🟣' : '🔗' }}</span>
              <span class="chain-name">{{ chain.name }}</span>
              <el-tag v-if="chain.is_myfw" size="small" type="success">平台管理</el-tag>
              <el-tag size="small" type="info">{{ chain.rules.length }} 条规则</el-tag>
            </div>

            <!-- 跳转规则 -->
            <div v-if="chain.jump_rule" class="chain-jump">
              <span class="jump-line">│</span>
              <span class="jump-arrow">▼</span>
              <code class="jump-rule">{{ chain.jump_rule }}</code>
            </div>

            <!-- 规则列表 -->
            <div v-if="chain.rules && chain.rules.length > 0" class="rule-list">
              <div
                v-for="(rule, idx) in chain.rules"
                :key="idx"
                class="rule-item"
                :class="{
                  'is-myfw': rule.is_myfw,
                  'is-external': !rule.is_myfw
                }"
                @click="showRuleDetail(rule, chain.name)"
              >
                <span class="rule-index">{{ idx + 1 }}</span>
                <span class="rule-source-dot" :class="rule.is_myfw ? 'myfw' : 'external'" />
                <code class="rule-spec">{{ rule.raw }}</code>
              </div>
            </div>

            <div v-else class="empty-chain">
              <span>(空链)</span>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="empty-state">
        <el-empty description="暂无规则数据" />
      </div>
    </div>

    <!-- 新增/编辑策略对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="650px" :close-on-click-modal="false">
      <el-form :model="policyForm" :rules="formRules" ref="policyFormRef" label-width="90px">
        <el-form-item label="策略名称" prop="name">
          <el-input v-model="policyForm.name" placeholder="例如: 允许SSH远程管理" />
        </el-form-item>
        <el-form-item label="方向" prop="direction">
          <el-select v-model="policyForm.direction" style="width: 100%">
            <el-option label="入站 (INBOUND)" value="INBOUND" />
            <el-option label="出站 (OUTBOUND)" value="OUTBOUND" />
            <el-option label="转发 (FORWARD)" value="FORWARD" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源地址" class="form-col">
            <el-input v-model="policyForm.source" placeholder="IP/CIDR, 空表示任意" />
          </el-form-item>
          <el-form-item label="目标地址" class="form-col">
            <el-input v-model="policyForm.destination" placeholder="IP/CIDR, 空表示任意" />
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="policyForm.source_group" clearable placeholder="引用地址组(多 CIDR 匹配)">
              <el-option v-for="g in addressGroups" :key="g.id" :label="`${g.name} (${g.kind})`" :value="g.name" />
            </el-select>
          </el-form-item>
          <el-form-item label="目的地址组" class="form-col">
            <el-select v-model="policyForm.destination_group" clearable placeholder="引用地址组(多 CIDR 匹配)">
              <el-option v-for="g in addressGroups" :key="g.id" :label="`${g.name} (${g.kind})`" :value="g.name" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="协议" prop="protocol" class="form-col">
            <el-select v-model="policyForm.protocol" style="width: 100%">
              <el-option label="任意" value="ANY" />
              <el-option label="TCP" value="TCP" />
              <el-option label="UDP" value="UDP" />
              <el-option label="ICMP" value="ICMP" />
            </el-select>
          </el-form-item>
          <el-form-item label="端口范围" class="form-col">
            <el-input v-model="policyForm.port_range" placeholder="如: 22 或 80-8080" />
          </el-form-item>
        </div>
        <el-form-item label="动作" prop="action">
          <el-select v-model="policyForm.action" style="width: 100%">
            <el-option label="允许 (ACCEPT)" value="ACCEPT" />
            <el-option label="丢弃 (DROP)" value="DROP" />
            <el-option label="拒绝并回复 (REJECT)" value="REJECT" />
            <el-option label="标记 (MARK)" value="MARK" />
            <el-option label="DNAT 端口映射" value="DNAT" />
            <el-option label="SNAT 地址转换" value="SNAT" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="policyForm.action === 'DNAT' || policyForm.action === 'SNAT'" label="NAT目标">
          <el-input v-model="policyForm.nat_to" placeholder="例如: 192.168.1.100:8080" />
        </el-form-item>
        <el-form-item v-if="policyForm.action === 'MARK'" label="标记值">
          <el-input-number v-model="policyForm.mark" :min="1" :max="4294967295" controls-position="right" style="width: 200px" />
          <span class="form-hint">打标记动作的 mark 值</span>
        </el-form-item>
        <el-form-item label="匹配标记">
          <el-input-number v-model="policyForm.match_mark" :min="0" :max="4294967295" controls-position="right" style="width: 200px" />
          <span class="form-hint">填 &gt;0 表示仅匹配已打此 mark 的流量(与打标动作正交)</span>
        </el-form-item>
        <el-form-item label="分组">
          <el-input v-model="policyForm.group" placeholder="逻辑分组名,如 whitelist / business(可选)" />
        </el-form-item>
        <el-form-item label="优先级" prop="priority">
          <el-slider v-model="policyForm.priority" :min="1" :max="100" :step="1" show-input />
        </el-form-item>
        <el-form-item label="目标节点" prop="targets">
          <el-select v-model="selectedNodeIds" multiple placeholder="选择目标节点" style="width: 100%">
            <el-option
              v-for="node in availableNodes"
              :key="node.id"
              :label="`${node.hostname || node.id} (${node.ip || '无IP'})`"
              :value="node.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="policyForm.description" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="policyForm.enabled" />
        </el-form-item>
      </el-form>
      <!-- 实时命令预览:随表单勾选/填写即时生成底层 iptables 命令,无感教学 -->
      <div class="cmd-preview">
        <div class="cmd-preview-head">
          <span class="cmd-preview-title">命令预览</span>
          <span v-if="previewHint" class="cmd-preview-warn">⚠ {{ previewHint }}</span>
        </div>
        <pre class="cmd-preview-code">{{ previewCommand }}</pre>
        <div class="cmd-preview-note">规则追加至 MYFW 自定义链,系统链已自动跳转,不影响 DOCKER / KUBE 等现有规则</div>
      </div>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="savePolicy" :loading="saving">确定</el-button>
      </template>
    </el-dialog>

    <!-- 查看策略详情对话框 -->
    <el-dialog v-model="viewDialogVisible" title="策略详情" width="600px">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="ID">{{ viewPolicyData.id }}</el-descriptions-item>
        <el-descriptions-item label="策略名称">{{ viewPolicyData.name }}</el-descriptions-item>
        <el-descriptions-item label="方向">
          <el-tag :type="getDirectionType(viewPolicyData.direction)">{{ getDirectionLabel(viewPolicyData.direction) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="动作">
          <el-tag :type="getActionType(viewPolicyData.action)">{{ getActionLabel(viewPolicyData.action) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="源地址">{{ viewPolicyData.source || '任意' }}</el-descriptions-item>
        <el-descriptions-item label="目标地址">{{ viewPolicyData.destination || '任意' }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ viewPolicyData.protocol || 'ANY' }}</el-descriptions-item>
        <el-descriptions-item label="端口">{{ viewPolicyData.port_range || '-' }}</el-descriptions-item>
        <el-descriptions-item label="优先级">{{ viewPolicyData.priority }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="viewPolicyData.enabled ? 'success' : 'info'">{{ viewPolicyData.enabled ? '已启用' : '已禁用' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="目标节点" :span="2">
          <template v-if="getPolicyTargets(viewPolicyData).length > 0">
            <el-tooltip
              v-for="nodeId in getPolicyTargets(viewPolicyData)"
              :key="nodeId"
              :content="nodeId"
              placement="top"
            >
              <el-tag size="small" type="info" style="margin: 2px">
                <span class="target-ip">{{ getNodeDisplay(nodeId).ip || getNodeDisplay(nodeId).hostname || nodeId.slice(0, 12) }}</span>
                <span v-if="getNodeDisplay(nodeId).hostname && getNodeDisplay(nodeId).ip" class="target-host">{{ getNodeDisplay(nodeId).hostname }}</span>
              </el-tag>
            </el-tooltip>
          </template>
          <span v-else>-</span>
        </el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">{{ viewPolicyData.description || '-' }}</el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ formatDate(viewPolicyData.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ formatDate(viewPolicyData.updated_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 批量应用对话框 -->
    <el-dialog v-model="batchApplyVisible" title="批量应用到主机" width="500px">
      <el-select v-model="batchApplyNodeIds" multiple placeholder="选择目标主机" style="width: 100%">
        <el-option
          v-for="node in allNodes.filter(n => n.status === 'ACTIVE')"
          :key="node.id"
          :label="`${node.hostname || node.id} (${node.ip || '无IP'})`"
          :value="node.id"
        />
      </el-select>
      <template #footer>
        <el-button @click="batchApplyVisible = false">取消</el-button>
        <el-button type="primary" @click="executeBatchApply" :loading="batchApplyLoading">应用</el-button>
      </template>
    </el-dialog>

    <!-- 策略版本与审批对话框 -->
    <el-dialog v-model="versionDialogVisible" title="策略版本与审批" width="760px">
      <el-table :data="versions" v-loading="versionLoading" size="small">
        <el-table-column label="版本" width="80" align="center">
          <template #default="{ row }">v{{ row.version }}</template>
        </el-table-column>
        <el-table-column prop="author" label="提交人" width="120" />
        <el-table-column label="状态" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="versionStatusType(row.status)" size="small">{{ versionStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="时间">
          <template #default="{ row }">{{ row.created_at ? new Date(row.created_at).toLocaleString() : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="180" align="center">
          <template #default="{ row }">
            <template v-if="row.status === 'pending'">
              <el-button size="small" type="success" @click="approveVersion(row)">通过</el-button>
              <el-button size="small" type="danger" @click="rejectVersion(row)">拒绝</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, Plus, Refresh, Connection, Warning } from '@element-plus/icons-vue'
import {
  getPolicies, createPolicy, updatePolicy, deletePolicy as apiDeletePolicy,
  submitPolicyChange, getPolicyVersions, approvePolicyVersion, rejectPolicyVersion,
  applyPolicy as apiApplyPolicy, applyAllPolicies, getNodes,
  batchTogglePolicies, batchDeletePolicies, batchApplyToNodes,
  detectConflicts, getChainTree, getAddressGroups
} from '@/api'

// 状态
const loading = ref(false)
const saving = ref(false)
const applyingAll = ref(false)
const checkingConflicts = ref(false)
const expertMode = ref(false)
const policies = ref([])
const allNodes = ref([])
const addressGroups = ref([])
const selectedIds = ref([])
const conflicts = ref([])

// 筛选
const searchKeyword = ref('')
const filterDirection = ref('')
const filterAction = ref('')
const filterEnabled = ref('')
const selectedHosts = ref([])
const hostSearch = ref('')

// 对话框
const dialogVisible = ref(false)
const viewDialogVisible = ref(false)
const dialogTitle = ref('新增策略')
const policyFormRef = ref(null)
const selectedNodeIds = ref([])

// 专家模式
const selectedExpertNode = ref('')
const chainTreeLoading = ref(false)
const chainTree = ref({})

// 批量应用
const batchApplyVisible = ref(false)
const batchApplyNodeIds = ref([])
const batchApplyLoading = ref(false)

// 表单数据
const policyForm = reactive({
  name: '',
  direction: 'INBOUND',
  source: '',
  destination: '',
  protocol: 'ANY',
  port_range: '',
  action: 'ACCEPT',
  mark: 0,
  nat_to: '',
  source_group: '',
  destination_group: '',
  match_mark: 0,
  group: '',
  priority: 50,
  description: '',
  targets: { node_ids: [], labels: [] },
  enabled: true
})

// 命令预览:复刻后端 internal/agent/driver/iptables 的 compileRule/targetChainFor 逻辑,
// 让用户填写表单时即时看到将生成的底层 iptables 命令。表/链映射与动作目标须与后端一致。
const buildPreviewCommand = (f) => {
  // 表/链映射:DNAT/SNAT/MARK 走 nat/mangle,其余按方向走 filter
  let table = 'filter'
  let chain = 'MYFW-INPUT'
  switch (f.action) {
    case 'DNAT': table = 'nat'; chain = 'MYFW-PREROUTING'; break
    case 'SNAT': table = 'nat'; chain = 'MYFW-POSTROUTING'; break
    case 'MARK': table = 'mangle'; chain = 'MYFW-MANGLE'; break
    default:
      chain = { INBOUND: 'MYFW-INPUT', OUTBOUND: 'MYFW-OUTPUT', FORWARD: 'MYFW-FORWARD' }[f.direction] || 'MYFW-INPUT'
  }
  const parts = ['iptables', '-t', table, '-A', chain]
  if (f.source) parts.push('-s', f.source)
  if (f.destination) parts.push('-d', f.destination)
  const proto = { TCP: 'tcp', UDP: 'udp', ICMP: 'icmp' }[f.protocol] || ''
  if (proto) parts.push('-p', proto)
  if (f.port_range) parts.push('--dport', String(f.port_range).replace(/-/g, ':'))
  if (f.source_group) parts.push('-m', 'set', '--match-set', `MYFW-${f.source_group}`, 'src')
  if (f.destination_group) parts.push('-m', 'set', '--match-set', `MYFW-${f.destination_group}`, 'dst')
  if (f.match_mark > 0) parts.push('-m', 'mark', '--mark', String(f.match_mark))
  switch (f.action) {
    case 'ACCEPT': parts.push('-j', 'ACCEPT'); break
    case 'DROP': parts.push('-j', 'DROP'); break
    case 'REJECT': parts.push('-j', 'REJECT'); break
    case 'MARK': parts.push('-j', 'MARK', '--set-mark', String(f.mark || 0)); break
    case 'DNAT': parts.push('-j', 'DNAT', '--to-destination', f.nat_to || '<NAT目标>'); break
    case 'SNAT': parts.push('-j', 'SNAT', '--to-source', f.nat_to || '<NAT目标>'); break
  }
  return parts.join(' ')
}

const previewCommand = computed(() => buildPreviewCommand(policyForm))
const previewHint = computed(() => {
  const f = policyForm
  if (f.port_range && f.protocol !== 'TCP' && f.protocol !== 'UDP') return '端口范围需指定 TCP/UDP 协议,否则后端将拒绝'
  if ((f.action === 'DNAT' || f.action === 'SNAT') && !f.nat_to) return 'NAT 动作需填写 NAT 目标'
  return ''
})

const formRules = {
  name: [{ required: true, message: '请输入策略名称', trigger: 'blur' }],
  direction: [{ required: true, message: '请选择方向', trigger: 'change' }],
  action: [{ required: true, message: '请选择动作', trigger: 'change' }]
}

const viewPolicyData = reactive({
  id: '', name: '', direction: '', source: '', destination: '',
  protocol: '', port_range: '', action: '', priority: 0,
  enabled: false, targets: '', description: '', created_at: '', updated_at: ''
})

// 可用节点
const availableNodes = computed(() => allNodes.value.filter(n => n.status === 'ACTIVE'))

// 过滤后的主机
const filteredHosts = computed(() => {
  const kw = hostSearch.value.toLowerCase()
  return allNodes.value.map(n => ({
    ...n,
    _selected: selectedHosts.value.some(s => s.id === n.id)
  })).filter(n => !kw || (n.hostname || '').toLowerCase().includes(kw) || (n.id || '').toLowerCase().includes(kw))
})

// 过滤后的策略
const filteredPolicies = computed(() => {
  return policies.value.filter(p => {
    if (searchKeyword.value) {
      const kw = searchKeyword.value.toLowerCase()
      const match = (p.name || '').toLowerCase().includes(kw) ||
                    (p.source || '').toLowerCase().includes(kw) ||
                    (p.destination || '').toLowerCase().includes(kw)
      if (!match) return false
    }
    if (filterDirection.value && p.direction !== filterDirection.value) return false
    if (filterAction.value && p.action !== filterAction.value) return false
    if (filterEnabled.value !== '' && p.enabled !== filterEnabled.value) return false
    // 主机筛选
    if (selectedHosts.value.length > 0) {
      const targets = getPolicyTargets(p)
      const hasOverlap = selectedHosts.value.some(h => targets.includes(h.id))
      if (!hasOverlap) return false
    }
    return true
  })
})

// 工具函数
const getDirectionLabel = (d) => {
  const map = { INBOUND: '入站', OUTBOUND: '出站', FORWARD: '转发' }
  return map[d] || d || '-'
}
const getDirectionIcon = (d) => {
  const map = { INBOUND: '→', OUTBOUND: '←', FORWARD: '⇄' }
  return map[d] || '•'
}
const getDirectionType = (d) => {
  const map = { INBOUND: 'success', OUTBOUND: 'warning', FORWARD: 'info' }
  return map[d] || 'info'
}
const getActionLabel = (a) => {
  const map = { ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '标记', DNAT: 'DNAT', SNAT: 'SNAT' }
  return map[a] || a || '-'
}
const getActionIcon = (a) => {
  const map = { ACCEPT: '✅', DROP: '🚫', REJECT: '❌', MARK: '🏷️', DNAT: '🔀', SNAT: '🔀' }
  return map[a] || '•'
}
const getActionType = (a) => {
  const map = { ACCEPT: 'success', DROP: 'danger', REJECT: 'warning', MARK: 'info' }
  return map[a] || 'info'
}
const getPriorityClass = (p) => {
  if (p <= 50) return 'high'
  if (p <= 100) return 'medium'
  return 'low'
}
const getPolicyTargets = (p) => {
  if (!p.targets) return []
  try {
    const t = typeof p.targets === 'string' ? JSON.parse(p.targets) : p.targets
    return t.node_ids || []
  } catch { return [] }
}
const getNodeName = (id) => {
  const node = allNodes.value.find(n => n.id === id)
  return node ? (node.hostname || node.id) : id
}
// 节点展示信息：IP 作为主键，hostname 作副标题，nodeId 仅用于 tooltip/URL 参数
const getNodeDisplay = (id) => {
  const node = allNodes.value.find(n => n.id === id)
  return {
    ip: node?.ip || '',
    hostname: node?.hostname || '',
    id
  }
}
const formatDate = (d) => {
  if (!d) return '-'
  try { return new Date(d).toLocaleString() } catch { return d }
}

// 加载数据
const loadData = async () => {
  loading.value = true
  try {
    const [policiesData, nodesData, groupsData] = await Promise.all([getPolicies(), getNodes(), getAddressGroups()])
    policies.value = (policiesData.policies || []).map(p => ({ ...p, _applying: false }))
    allNodes.value = nodesData.nodes || []
    addressGroups.value = groupsData.address_groups || []
  } catch {
    ElMessage.error('加载数据失败')
  } finally {
    loading.value = false
  }
}

// 筛选操作
const handleSearch = () => {}
const resetSearch = () => {
  searchKeyword.value = ''
  filterDirection.value = ''
  filterAction.value = ''
  filterEnabled.value = ''
  selectedHosts.value = []
}

// 主机筛选
const onHostSelectionChange = () => {
  selectedHosts.value = filteredHosts.value.filter(n => n._selected)
}
const selectAllHosts = () => {
  allNodes.value.forEach(n => n._selected = true)
  selectedHosts.value = [...allNodes.value]
}
const clearHosts = () => {
  allNodes.value.forEach(n => n._selected = false)
  selectedHosts.value = []
}

// 选择操作
const toggleSelect = (id) => {
  const idx = selectedIds.value.indexOf(id)
  if (idx >= 0) selectedIds.value.splice(idx, 1)
  else selectedIds.value.push(id)
}

// 批量操作
const handleBatchToggle = async (enabled) => {
  try {
    await batchTogglePolicies(selectedIds.value, enabled)
    ElMessage.success(`已${enabled ? '启用' : '禁用'} ${selectedIds.value.length} 条策略`)
    selectedIds.value = []
    loadData()
  } catch {
    ElMessage.error('操作失败')
  }
}
const handleBatchDelete = async () => {
  try {
    await ElMessageBox.confirm(`确定删除 ${selectedIds.value.length} 条策略?`, '确认', { type: 'warning' })
    await batchDeletePolicies(selectedIds.value)
    ElMessage.success('已删除')
    selectedIds.value = []
    loadData()
  } catch {}
}
const showBatchApplyDialog = () => {
  batchApplyNodeIds.value = []
  batchApplyVisible.value = true
}
const executeBatchApply = async () => {
  if (batchApplyNodeIds.value.length === 0) {
    ElMessage.warning('请选择目标主机')
    return
  }
  batchApplyLoading.value = true
  try {
    await batchApplyToNodes(selectedIds.value, batchApplyNodeIds.value)
    ElMessage.success('已创建应用任务')
    batchApplyVisible.value = false
    selectedIds.value = []
  } catch {
    ElMessage.error('应用失败')
  } finally {
    batchApplyLoading.value = false
  }
}

// 冲突检测
const detectPolicyConflicts = async () => {
  if (selectedIds.value.length < 2) {
    ElMessage.warning('请先选择至少 2 条策略')
    return
  }
  checkingConflicts.value = true
  try {
    const data = await detectConflicts(selectedIds.value)
    conflicts.value = data.conflicts || []
    if (conflicts.value.length === 0) {
      ElMessage.success('未检测到冲突')
    }
  } catch {
    ElMessage.error('检测失败')
  } finally {
    checkingConflicts.value = false
  }
}

// CRUD 操作
const openAddDialog = () => {
  dialogTitle.value = '新增策略'
  Object.assign(policyForm, {
    name: '', direction: 'INBOUND', source: '', destination: '',
    protocol: 'ANY', port_range: '', action: 'ACCEPT',
    mark: 0, nat_to: '', source_group: '', destination_group: '',
    match_mark: 0, group: '', priority: 50, description: '',
    targets: { node_ids: [], labels: [] }, enabled: true
  })
  selectedNodeIds.value = []
  dialogVisible.value = true
}
const editPolicy = (p) => {
  dialogTitle.value = '编辑策略'
  Object.assign(policyForm, {
    name: p.name, direction: p.direction, source: p.source,
    destination: p.destination, protocol: p.protocol, port_range: p.port_range,
    action: p.action, mark: p.mark || 0, nat_to: p.nat_to || '',
    source_group: p.source_group || '', destination_group: p.destination_group || '',
    match_mark: p.match_mark || 0, group: p.group || '',
    priority: p.priority, description: p.description || '', enabled: p.enabled
  })
  selectedNodeIds.value = getPolicyTargets(p)
  policyForm._editingId = p.id
  dialogVisible.value = true
}
const savePolicy = async () => {
  if (!policyFormRef.value) return
  await policyFormRef.value.validate()
  saving.value = true
  try {
    const data = {
      ...policyForm,
      targets: { node_ids: selectedNodeIds.value, labels: [] }
    }
    if (policyForm._editingId) {
      await submitPolicyChange(policyForm._editingId, data)
      ElMessage.success('变更已提交，待审批（在版本列表中通过后生效并下发）')
    } else {
      await createPolicy(data)
      ElMessage.success('创建成功')
    }
    dialogVisible.value = false
    loadData()
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '操作失败')
  } finally {
    saving.value = false
  }
}
const viewPolicy = (p) => {
  Object.assign(viewPolicyData, p)
  viewDialogVisible.value = true
}

// 策略版本与审批（阶段5）
const versionDialogVisible = ref(false)
const versionLoading = ref(false)
const versions = ref([])
const currentVersionPolicyId = ref(0)

const viewVersions = async (p) => {
  currentVersionPolicyId.value = p.id
  versionDialogVisible.value = true
  versionLoading.value = true
  try {
    const data = await getPolicyVersions(p.id)
    versions.value = data.versions || []
  } catch {
    ElMessage.error('加载版本失败')
  } finally {
    versionLoading.value = false
  }
}

const approveVersion = async (v) => {
  try {
    await approvePolicyVersion(currentVersionPolicyId.value, v.id)
    ElMessage.success('已通过，关联节点已触发下发')
    viewVersions({ id: currentVersionPolicyId.value })
    loadData()
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '审批失败')
  }
}

const rejectVersion = async (v) => {
  try {
    await rejectPolicyVersion(currentVersionPolicyId.value, v.id)
    ElMessage.success('已拒绝')
    viewVersions({ id: currentVersionPolicyId.value })
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '拒绝失败')
  }
}

const versionStatusType = (s) => ({ pending: 'warning', approved: 'success', rejected: 'danger' }[s] || 'info')
const versionStatusLabel = (s) => ({ pending: '待审批', approved: '已通过', rejected: '已拒绝' }[s] || s)
const handleDelete = async (p) => {
  try {
    await ElMessageBox.confirm(`确定删除策略 ${p.name}?`, '确认', { type: 'warning' })
    await apiDeletePolicy(p.id)
    ElMessage.success('已删除')
    loadData()
  } catch {}
}
const handleApply = async (p) => {
  p._applying = true
  try {
    await applyPolicy(p.id, { auto_approve: true })
    ElMessage.success('已应用')
  } catch {
    ElMessage.error('应用失败')
  } finally {
    p._applying = false
  }
}
const handleApplyAll = async () => {
  applyingAll.value = true
  try {
    await applyAllPolicies({ auto_approve: true })
    ElMessage.success('全量应用已提交')
  } catch {
    ElMessage.error('应用失败')
  } finally {
    applyingAll.value = false
  }
}

// 专家模式
const loadChainTree = async () => {
  if (!selectedExpertNode.value) return
  chainTreeLoading.value = true
  try {
    const data = await getChainTree(selectedExpertNode.value)
    chainTree.value = data
  } catch {
    ElMessage.error('加载链结构失败')
    chainTree.value = {}
  } finally {
    chainTreeLoading.value = false
  }
}
const showRuleDetail = (rule, chainName) => {
  ElMessage.info(`${chainName}: ${rule.raw}`)
}

onMounted(loadData)
</script>

<style scoped>
.policies-page { width: 100%; }

/* 页面头部 */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { margin: 0; font-size: 20px; font-weight: 600; color: #1E293B; }

/* 筛选栏 */
.filter-bar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  padding: 16px;
  background: #fff;
  border-radius: 6px;
  border: 1px solid #E2E8F0;
}
.host-badge { margin-left: 4px; }

/* 主机筛选面板 */
.host-filter-panel { max-height: 300px; }
.host-list { max-height: 200px; overflow-y: auto; }
.host-item { display: inline-flex; align-items: center; gap: 8px; }
.host-name { font-weight: 500; }
.host-ip { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #64748B; }
.host-actions { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding-top: 12px; border-top: 1px solid #E2E8F0; }
.host-count { font-size: 12px; color: #64748B; }

/* 批量操作栏 */
.batch-bar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: #EFF6FF;
  border-radius: 6px;
  border: 1px solid #BFDBFE;
}
.batch-count { font-weight: 500; color: #1E40AF; }

/* 操作按钮栏 */
.action-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

/* 冲突提示 */
.conflicts-section { margin-bottom: 16px; }
.conflict-item { display: flex; align-items: center; gap: 8px; padding: 4px 0; }

/* 简易模式 - 云安全组风格列表 */
.policy-list { display: flex; flex-direction: column; gap: 12px; }
.policy-row {
  position: relative;
  background: #fff;
  border: 1px solid #E2E8F0;
  border-radius: 6px;
  padding: 16px 16px 12px 20px;
  transition: all 0.2s;
}
.policy-row:hover { border-color: #3B82F6; box-shadow: 0 2px 8px rgba(59, 130, 246, 0.1); }
.policy-row.selected { border-color: #3B82F6; background: #EFF6FF; }
.policy-row.disabled { opacity: 0.6; }

/* 优先级色条 */
.priority-bar {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 4px;
  border-radius: 6px 0 0 6px;
}
.priority-bar.high { background: #EF4444; }
.priority-bar.medium { background: #F59E0B; }
.priority-bar.low { background: #94A3B8; }

/* 行头 */
.row-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.priority-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: #64748B;
  background: #F1F5F9;
  padding: 2px 8px;
  border-radius: 4px;
}
.policy-name { font-size: 15px; font-weight: 600; color: #1E293B; flex: 1; }
.row-actions { display: flex; gap: 4px; }

/* 规则摘要 */
.rule-summary {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 12px;
  background: #F8FAFC;
  border-radius: 4px;
  margin-bottom: 8px;
}
.direction-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}
.direction-tag.inbound { background: #DCFCE7; color: #166534; }
.direction-tag.outbound { background: #FEF3C7; color: #92400E; }
.direction-tag.forward { background: #E0E7FF; color: #3730A3; }

.field { display: flex; flex-direction: column; gap: 2px; }
.field-label { font-size: 11px; color: #94A3B8; text-transform: uppercase; }
.field-value { font-size: 13px; color: #1E293B; }
.field-value.mono { font-family: 'JetBrains Mono', monospace; }

.action-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  margin-left: auto;
}
.action-tag.accept { background: #DCFCE7; color: #166534; }
.action-tag.drop { background: #FEE2E2; color: #991B1B; }
.action-tag.reject { background: #FEF3C7; color: #92400E; }
.action-tag.mark, .action-tag.dnat, .action-tag.snat { background: #E0E7FF; color: #3730A3; }

/* 关联信息 */
.relation-info {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 12px;
  color: #64748B;
}
.targets { display: flex; align-items: center; gap: 6px; }
.target-tag { margin: 0 2px; }
.target-ip { font-family: 'JetBrains Mono', monospace; }
.target-host { margin-left: 6px; font-size: 11px; opacity: 0.7; }
.desc { font-style: italic; }

/* 命令预览窗(新增策略 dialog 底部,实时展示底层 iptables 命令) */
.cmd-preview { margin-top: 12px; border: 1px solid #E2E8F0; border-radius: 6px; overflow: hidden; }
.cmd-preview-head { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #F1F5F9; border-bottom: 1px solid #E2E8F0; }
.cmd-preview-title { font-size: 12px; font-weight: 600; color: #1E293B; }
.cmd-preview-warn { font-size: 12px; color: #f56c6c; }
.cmd-preview-code { margin: 0; padding: 12px; background: #1E293B; color: #E2E8F0; font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
.cmd-preview-note { padding: 8px 12px; font-size: 12px; color: #64748B; background: #F8FAFC; }

/* 专家模式 */
.expert-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  padding: 16px;
  background: #fff;
  border-radius: 6px;
  border: 1px solid #E2E8F0;
}
.chain-tree { display: flex; flex-direction: column; gap: 20px; }

.table-section {
  background: #fff;
  border: 1px solid #E2E8F0;
  border-radius: 6px;
  overflow: hidden;
}
.table-header {
  padding: 12px 16px;
  background: #F1F5F9;
  border-bottom: 1px solid #E2E8F0;
}
.table-title { margin: 0; font-size: 14px; font-weight: 600; color: #1E293B; }

.chain-block {
  padding: 16px;
  border-bottom: 1px solid #F1F5F9;
}
.chain-block:last-child { border-bottom: none; }
.chain-block.is-myfw { background: #FAF5FF; }

.chain-node {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.chain-icon { font-size: 16px; }
.chain-name { font-weight: 600; color: #1E293B; }

.chain-jump {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 8px 0 8px 24px;
  color: #64748B;
  font-size: 12px;
}
.jump-line { color: #CBD5E1; }
.jump-arrow { color: #3B82F6; }
.jump-rule { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #64748B; }

.rule-list {
  margin-left: 24px;
  border-left: 2px solid #E2E8F0;
}
.rule-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  cursor: pointer;
  transition: background 0.15s;
}
.rule-item:hover { background: #F1F5F9; }
.rule-item.is-myfw { border-left: 3px solid #8B5CF6; }
.rule-item.is-external { border-left: 3px solid #94A3B8; }

.rule-index {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: #94A3B8;
  min-width: 20px;
}
.rule-source-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.rule-source-dot.myfw { background: #8B5CF6; }
.rule-source-dot.external { background: #94A3B8; }
.rule-spec {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: #1E293B;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.empty-chain {
  margin-left: 24px;
  padding: 8px 12px;
  color: #94A3B8;
  font-size: 12px;
  font-style: italic;
}

.empty-state { padding: 40px; text-align: center; }
.loading-state { padding: 20px; }

/* 表单布局 */
.form-row { display: flex; gap: 16px; }
.form-col { flex: 1; }
.form-hint { margin-left: 12px; font-size: 12px; color: #94a3b8; }
</style>
