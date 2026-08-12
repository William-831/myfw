<template>
  <div class="np-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">节点策略</h2>
        <el-tag size="small" type="info">以节点为中心管理策略实例</el-tag>
      </div>
      <div class="header-right">
        <el-switch v-model="expertMode" active-text="专家终端" inactive-text="实例配置" />
      </div>
    </div>
    <ExpertMode v-if="expertMode" />
    <el-alert
      v-if="guardTask"
      type="warning"
      :closable="false"
      class="guard-banner"
      @click="guard.open()"
    >
      <span>⏰ 该节点有保护期待确认任务 — 操作者 {{ guardTask.reviewer || '-' }}，{{ guardTask.policy_name || '节点策略' }}，点击前往确认</span>
    </el-alert>
    <el-row v-else :gutter="14" class="np-body">
      <!-- 左:节点列表 -->
      <el-col :span="6">
        <el-card class="node-card" v-loading="nodesLoading">
          <template #header><span>节点</span></template>
          <div v-if="!nodes.length && !nodesLoading" class="empty-mini">暂无节点</div>
          <div v-for="n in nodes" :key="n.id" class="node-item" :class="{ active: n.id === selectedNodeId }" @click="selectNode(n)">
            <el-badge :value="n.drift_count" :hidden="!n.drift_count" class="node-badge" type="warning">
              <span class="node-ip">{{ n.ip || n.hostname || n.id.slice(0, 12) }}</span>
            </el-badge>
            <el-tag :type="n.status === 'ACTIVE' ? 'success' : 'info'" size="small">{{ n.status === 'ACTIVE' ? '在线' : '离线' }}</el-tag>
          </div>
        </el-card>
      </el-col>
      <!-- 右:实例列表 -->
      <el-col :span="18">
        <el-card class="inst-card" v-loading="instLoading">
          <template #header>
            <div class="inst-head">
              <span>{{ currentNodeLabel }} 的策略实例 ({{ instances.length }})</span>
              <div class="inst-actions">
                <el-button size="small" type="primary" @click="openCreate" :disabled="!selectedNodeId"><el-icon><Plus /></el-icon>新建策略</el-button>
                <el-button size="small" @click="openInstantiate" :disabled="!selectedNodeId"><el-icon><Plus /></el-icon>从模板实例化</el-button>
                <el-button size="small" type="success" @click="handleDispatch" :disabled="!selectedNodeId || !instances.length" :loading="dispatching">下发节点(全量对齐)</el-button>
                <el-button size="small" type="warning" @click="handleSyncAll" :disabled="!selectedNodeId || !driftInstanceCount" :loading="syncingAll">同步全部漂移({{ driftInstanceCount }})</el-button>
                <el-button size="small" type="info" @click="openSimulate" :disabled="!selectedNodeId"><el-icon><Monitor /></el-icon>流量预演</el-button>
                <el-checkbox v-model="onlyDead" size="small" class="dead-filter">仅看死规则</el-checkbox>
              </div>
            </div>
          </template>
          <div v-if="!selectedNodeId" class="empty-mini">请选择左侧节点</div>
          <div v-else-if="!instances.length" class="empty-mini">该节点暂无策略实例,点"从模板实例化"添加</div>
          <div v-else class="inst-list">
            <div v-for="inst in sortedInstances" :key="inst.id" class="inst-item" :class="{ disabled: !inst.enabled, drift: inst.drift, 'not-applied': inst.enabled && !inst.applied }">
              <div class="inst-top">
                <span class="inst-name">{{ inst.name }}</span>
                <el-tag size="small" type="info">模板: {{ inst.template_name || '-' }}</el-tag>
                <el-tooltip v-if="inst.drift" :content="driftFieldsText(inst)" placement="top">
                  <el-tag type="warning" size="small" effect="dark">⚠ 模板已更新({{ inst.deviated_fields?.length || 0 }}字段)</el-tag>
                </el-tooltip>
                <el-tag v-if="inst.pending_delete" size="small" type="warning" effect="dark">待确认移除</el-tag>
                <el-tag v-else-if="inst.chain_unavailable" size="small" type="danger" effect="dark">⚠ 链不可用</el-tag>
                <el-tag v-else-if="inst.enabled && !inst.applied" size="small" type="warning" effect="dark">未下发</el-tag>
                <el-tag v-else-if="inst.enabled && inst.applied" size="small" type="success" effect="plain">已下发</el-tag>
                <el-tag v-else-if="!inst.enabled && inst.applied" size="small" type="danger" effect="dark">待移除</el-tag>
                <el-tag v-if="ruleHitsMap[inst.id]?.dead" size="small" type="info" effect="dark">死规则</el-tag>
                <el-tag :type="inst.enabled ? 'success' : 'info'" size="small">{{ inst.enabled ? '启用' : '禁用' }}</el-tag>
              </div>
              <div class="inst-rule">
                <span class="field"><span class="lbl">协议</span>{{ inst.protocol || 'ANY' }}</span>
                <span class="field"><span class="lbl">端口</span>{{ inst.port_range || '任意' }}</span>
                <span class="field"><span class="lbl">源</span>{{ inst.source || '任意' }}</span>
                <span class="field"><span class="lbl">目的</span>{{ inst.destination || '任意' }}</span>
                <span v-if="inst.source_group" class="field"><span class="lbl">源组</span>{{ inst.source_group }}</span>
                <span v-if="inst.destination_group" class="field"><span class="lbl">目的组</span>{{ inst.destination_group }}</span>
                <span class="action" :class="inst.action ? inst.action.toLowerCase() : ''">{{ getActionLabel(inst.action) }}</span>
              </div>
              <div class="inst-foot">
                <div class="foot-left">
                  <span class="prio">优先级 #{{ inst.priority }}</span>
                  <span class="hits">命中 {{ formatHits(ruleHitsMap[inst.id]) }}</span>
                  <el-switch :model-value="inst.enabled" size="small" @change="(v) => toggleEnabled(inst, v)" />
                </div>
                <div class="actions">
                  <el-button size="small" text type="warning" @click="openEditInst(inst)">编辑参数</el-button>
                  <el-button v-if="inst.drift" size="small" text type="primary" @click="handleSync(inst)">同步模板</el-button>
                  <el-button size="small" text type="danger" :disabled="inst.pending_delete" @click="handleDeleteInst(inst)">移除</el-button>
                </div>
              </div>
              <div class="inst-cmd">
                <code v-for="(line, i) in buildCommandPreview(inst, customChains)" :key="i" :class="'cmd-' + line.type">{{ line.text }}</code>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 流量预演(计划二:五元组仿真命中路径) -->
    <el-dialog v-model="simVisible" :title="'流量预演 — ' + currentNodeLabel" width="560px">
      <el-form label-width="90px">
        <el-form-item label="方向">
          <el-select v-model="simForm.direction" style="width: 100%">
            <el-option label="入站 INPUT" value="INPUT" />
            <el-option label="转发 FORWARD" value="FORWARD" />
            <el-option label="出站 OUTPUT" value="OUTPUT" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源 IP" class="form-col"><el-input v-model="simForm.source_ip" placeholder="如 192.168.1.5,空=任意" /></el-form-item>
          <el-form-item label="目的 IP" class="form-col"><el-input v-model="simForm.dest_ip" placeholder="如 10.0.0.1,空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="协议" class="form-col">
            <el-select v-model="simForm.protocol" style="width: 100%">
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="ICMP" value="icmp" />
              <el-option label="任意" value="" />
            </el-select>
          </el-form-item>
          <el-form-item label="目的端口" class="form-col"><el-input-number v-model="simForm.dst_port" :min="0" :max="65535" controls-position="right" style="width: 100%" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源端口" class="form-col"><el-input-number v-model="simForm.src_port" :min="0" :max="65535" controls-position="right" style="width: 100%" /></el-form-item>
        </div>
        <span class="form-hint">基于该节点当前期望规则集(编译产物)做 filter 表无状态匹配;NAT/mangle 仅提示不模拟,连接状态(ESTABLISHED)不建模。</span>
      </el-form>
      <div v-if="simResult" class="sim-result" :class="'verdict-' + simResult.verdict.toLowerCase()">
        <div class="sim-verdict">
          最终判定:
          <el-tag :type="verdictTagType(simResult.verdict)" size="large" effect="dark">{{ simResult.verdict }}</el-tag>
        </div>
        <div v-if="simResult.steps.length" class="sim-steps">
          <div class="sim-steps-title">命中路径(按遍历顺序)</div>
          <div v-for="(s, i) in simResult.steps" :key="i" class="sim-step" :class="{ 'is-hit': s.matched }">
            <span class="sim-idx">{{ i + 1 }}</span>
            <span class="sim-chain">{{ s.chain }}</span>
            <span class="sim-action" :class="s.matched ? 'hit' : ''">{{ s.action }}</span>
            <span class="sim-rule">{{ s.rule_id }}</span>
            <el-tag v-if="s.matched" size="small" type="success">命中</el-tag>
            <span v-if="s.note" class="sim-note">{{ s.note }}</span>
          </div>
        </div>
        <div v-else class="sim-empty">无规则参与匹配</div>
        <div v-if="simResult.note" class="sim-note-line">{{ simResult.note }}</div>
      </div>
      <template #footer>
        <el-button @click="simVisible = false">关闭</el-button>
        <el-button type="primary" @click="handleSimulate" :loading="simLoading">预演</el-button>
      </template>
    </el-dialog>

    <!-- 从模板实例化 -->
    <el-dialog v-model="instantiateVisible" title="从模板实例化" width="480px">
      <el-form label-width="90px">
        <el-form-item label="选择模板">
          <el-select v-model="instantiateForm.template_id" placeholder="模板" style="width: 100%">
            <el-option v-for="t in templates" :key="t.id" :label="`${t.name} (${t.action}, ${t.protocol || 'ANY'})`" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="实例名称"><el-input v-model="instantiateForm.name" placeholder="空则用模板名" /></el-form-item>
        <el-form-item v-if="isMarkTpl" label="源地址">
          <el-input v-model="instantiateForm.source" placeholder="白名单 IP/CIDR,如 192.168.1.5" />
        </el-form-item>
        <el-form-item v-if="isMarkTpl" label="源地址组">
          <el-select v-model="instantiateForm.source_group" clearable placeholder="白名单地址组(与源地址二选一)" style="width: 100%">
            <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="立即应用"><el-switch v-model="instantiateForm.apply" /></el-form-item>
        <span class="form-hint">实例化时从模板全量复制参数,之后模板修改不影响本实例</span>
      </el-form>
      <template #footer>
        <el-button @click="instantiateVisible = false">取消</el-button>
        <el-button type="primary" @click="handleInstantiate" :loading="instantiating">实例化</el-button>
      </template>
    </el-dialog>

    <!-- 新建/编辑策略(共用表单) -->
    <el-dialog v-model="formVisible" :title="isCreate ? '新建策略' : '编辑实例参数'" width="640px">
      <el-form :model="instForm" label-width="90px">
        <el-form-item label="实例名称"><el-input v-model="instForm.name" /></el-form-item>
        <el-form-item v-if="instForm.action !== 'MARK'" label="所属组">
          <el-select v-model="instForm.group_id" style="width: 100%">
            <el-option v-for="cc in customChains" :key="cc.id" :label="`${cc.name}${cc.description ? ' - ' + cc.description : ''}`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源地址" class="form-col"><el-input v-model="instForm.source" :placeholder="instForm.action === 'MARK' ? '白名单 IP/CIDR,如 192.168.1.5' : '空=任意'" /></el-form-item>
          <el-form-item v-if="instForm.action !== 'MARK'" label="目标地址" class="form-col"><el-input v-model="instForm.destination" placeholder="空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="instForm.source_group" clearable :placeholder="instForm.action === 'MARK' ? '白名单地址组(与源地址二选一)' : '空=不匹配组'" style="width: 100%">
              <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="instForm.action !== 'MARK'" label="目的地址组" class="form-col">
            <el-select v-model="instForm.destination_group" clearable placeholder="空=不匹配组" style="width: 100%">
              <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="协议" class="form-col">
            <el-select v-model="instForm.protocol" style="width: 100%"><el-option label="任意" value="ANY" /><el-option label="TCP" value="TCP" /><el-option label="UDP" value="UDP" /><el-option label="ICMP" value="ICMP" /></el-select>
          </el-form-item>
          <el-form-item label="端口范围" class="form-col"><el-input v-model="instForm.port_range" placeholder="如 80 或 1000:2000" /></el-form-item>
        </div>
        <el-form-item label="动作">
          <el-select v-model="instForm.action" style="width: 100%">
            <el-option-group label="流量控制">
              <el-option label="允许 ACCEPT" value="ACCEPT" />
              <el-option label="丢弃 DROP" value="DROP" />
              <el-option label="拒绝 REJECT" value="REJECT" />
            </el-option-group>
            <el-option-group label="地址转换">
              <el-option label="目的转换 DNAT" value="DNAT" />
              <el-option label="源转换 SNAT" value="SNAT" />
            </el-option-group>
            <el-option-group label="白名单拦截">
              <el-option label="端口白名单拦截 MARK" value="MARK" />
            </el-option-group>
          </el-select>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'MARK'" label="流量方向">
          <el-select v-model="instForm.direction" style="width: 100%">
            <el-option label="容器转发(Docker 端口映射)" value="FORWARD" />
            <el-option label="主机入站(本地服务)" value="INPUT" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'MARK'" label="标记值">
          <el-select v-model="instForm.mark" style="width: 100%" placeholder="选标记(标记管理中维护)">
            <el-option v-for="m in marks" :key="m.id" :label="`${m.name} (${m.value})`" :value="m.value" />
          </el-select>
          <span class="form-hint">选方向+源(地址或组)+端口+标记值,自动生成:打标 -> 白名单放行 -> 其余丢弃</span>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'DNAT' || instForm.action === 'SNAT'" label="NAT 目标"><el-input v-model="instForm.nat_to" placeholder="如 1.2.3.4 或 1.2.3.4:8080" /></el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="instForm.priority" style="width: 100%" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="instForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="instForm.enabled" /></el-form-item>
        <el-form-item v-if="isCreate" label="立即应用"><el-switch v-model="instForm.apply" /></el-form-item>
      </el-form>
      <div class="cmd-preview">
        <div class="cmd-preview-head">规则预览</div>
        <pre class="cmd-preview-code"><span v-for="(line, i) in previewCommand" :key="i" :class="'cmd-' + line.type">{{ line.text }}{{ i < previewCommand.length - 1 ? '\n' : '' }}</span></pre>
      </div>
      <template #footer>
        <el-button @click="formVisible = false">取消</el-button>
        <el-button type="primary" @click="saveInst" :loading="savingInst">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Monitor } from '@element-plus/icons-vue'
import ExpertMode from './ExpertMode.vue'
import { getNodes, getNodeInstances, createInstance, updateInstance, deleteInstance, syncInstance, syncInstancePreview, syncAllNode, dispatchNode, getTemplates, getCustomChains, getAddressGroups, getMarks, getTasks, getTask, simulateFlow, getNodeRuleHits } from '@/api'
import { useGuardStore } from '@/stores/guard'

const route = useRoute()
const guard = useGuardStore()
const guardTask = ref(null) // 该节点保护期待确认任务(跳转来时高亮提示)

const nodesLoading = ref(false)
const instLoading = ref(false)
const dispatching = ref(false)
const nodes = ref([])
const instances = ref([])
const ruleHitsMap = ref({}) // 规则命中率(规则活性分析):instance_id -> {packets,bytes,dead,last_seen}
const onlyDead = ref(false) // 仅看死规则过滤

// 排序:未下发(enabled && !applied)或待移除(!enabled && applied)置顶,其次按添加时间倒序(新在上)
const sortedInstances = computed(() => {
  let list = [...instances.value]
  if (onlyDead.value) {
    list = list.filter((i) => ruleHitsMap.value[i.id]?.dead)
  }
  return list.sort((a, b) => {
    const ap = (a.enabled && !a.applied) || (!a.enabled && a.applied) ? 0 : 1
    const bp = (b.enabled && !b.applied) || (!b.enabled && b.applied) ? 0 : 1
    if (ap !== bp) return ap - bp
    return new Date(b.created_at) - new Date(a.created_at)
  })
})
const templates = ref([])
const customChains = ref([])
const addressGroups = ref([])
const marks = ref([])
const selectedNodeId = ref('')
const expertMode = ref(false)

const currentNodeLabel = computed(() => {
  const n = nodes.value.find(x => x.id === selectedNodeId.value)
  return n ? (n.ip || n.hostname || n.id.slice(0, 12)) : '未选择'
})

const getActionLabel = (a) => ({ ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '白名单拦截', DNAT: 'DNAT', SNAT: 'SNAT' }[a] || a || '-')

// 命令预览纯函数:根据表单/实例字段拼接底层 iptables 命令(MARK 白名单 3 条骨架,其余单条)
// 列表项与编辑对话框共用,浏览时直观看到将生成的 iptables 命令,无感教学
const buildCommandPreview = (f, chains = []) => {
  // MARK 动作统一走白名单拦截骨架(3条规则),参数未填处用占位符提示
  if (f.action === 'MARK') {
    const acl = f.direction === 'INPUT' ? 'MYFW-MARKACL-IN' : 'MYFW-MARKACL-FWD'
    const pp = f.port_range
      ? (f.protocol && f.protocol !== 'ANY' ? `-p ${f.protocol.toLowerCase()} --dport ${f.port_range}` : `--dport ${f.port_range}`)
      : '<请填端口>'
    const m = f.mark ? String(f.mark) : '<选标记值>'
    const src = f.source ? `-s ${f.source}`
      : (f.source_group ? `-m set --match-set MYFW-${f.source_group} src` : '<请填源地址/组>')
    return [
      { text: `iptables -t mangle -A MYFW-MARKMANGLE ${pp} -j MARK --set-mark ${m}`, type: 'mark' },
      { text: `iptables -t filter -A ${acl} ${src} -m mark --mark ${m} -j ACCEPT`, type: 'accept' },
      { text: `iptables -t filter -A ${acl} -m mark --mark ${m} -j DROP`, type: 'drop' },
    ]
  }
  const cc = chains.find(c => c.id === f.group_id)
  const table = cc?.table || 'filter'
  const chain = cc ? `MYFW-${cc.name}` : 'MYFW-INPUT'
  const parts = ['iptables', '-t', table, '-A', chain]
  if (f.source) parts.push('-s', f.source)
  if (f.destination) parts.push('-d', f.destination)
  if (f.source_group) parts.push('-m', 'set', '--match-set', 'MYFW-' + f.source_group, 'src')
  if (f.destination_group) parts.push('-m', 'set', '--match-set', f.destination_group, 'dst')
  if (f.protocol && f.protocol !== 'ANY') {
    parts.push('-p', f.protocol.toLowerCase())
    if (f.port_range && f.protocol !== 'ICMP') parts.push('--dport', f.port_range)
  }
  if (f.action === 'MARK') {
    parts.push('-j', 'MARK', '--set-mark', String(f.mark || 0))
  } else if (f.action === 'DNAT') {
    parts.push('-j', 'DNAT', ...(f.nat_to ? ['--to-destination', f.nat_to] : []))
  } else if (f.action === 'SNAT') {
    parts.push('-j', 'SNAT', ...(f.nat_to ? ['--to-source', f.nat_to] : []))
  } else if (f.action) {
    parts.push('-j', f.action)
  }
  return [{ text: parts.join(' '), type: 'default' }]
}

// 编辑对话框命令预览:响应式跟踪 instForm 与 customChains
const previewCommand = computed(() => buildCommandPreview(instForm, customChains.value))

// 轮询 task 直到终态(confirm_wait/confirmed/failed/rolled_back)或超时(15s)。
// 后端 dispatch 异步:Send 后 task 处于 applying,Agent 回 TaskResult 后才更新 applied。
// 不轮询会因 applied 延迟导致前端显示"未下发"而规则实际已生效。
const pollTaskDone = async (taskID) => {
  const terminal = new Set(['confirm_wait', 'confirmed', 'failed', 'rolled_back'])
  for (let i = 0; i < 15; i++) {
    await new Promise(r => setTimeout(r, 1000))
    try {
      const t = await getTask(taskID)
      if (terminal.has(t.status)) return t
    } catch {}
  }
  return null
}

// 一键启停:切换实例 enabled 后自动下发,轮询终态再刷新
const toggleEnabled = async (inst, v) => {
  try {
    await updateInstance(inst.id, { ...inst, enabled: v })
    const d = await dispatchNode(selectedNodeId.value, { auto_approve: true })
    const taskID = d.tasks?.[0]?.id
    if (!taskID) { ElMessage.success(v ? '已启用' : '已禁用'); loadInstances(); return }
    const t = await pollTaskDone(taskID)
    if (!t) { ElMessage.warning(v ? '已启用,下发超时,请稍后查看' : '已禁用,下发超时,请稍后查看'); loadInstances(); guard.refresh(); return }
    if (t.status === 'confirm_wait' || t.status === 'confirmed') {
      ElMessage.success(v ? '已启用并下发,请到顶部确认' : '已禁用并下发,请到顶部确认')
    } else {
      ElMessage.error((v ? '启用' : '禁用') + '下发失败: ' + (t.message || t.status))
    }
    loadInstances()
    guard.refresh()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '切换失败')
    loadInstances()
  }
}

const loadNodes = async () => {
  nodesLoading.value = true
  try {
    const d = await getNodes()
    nodes.value = d.nodes || []
  } catch {
    ElMessage.error('加载节点失败')
  } finally {
    nodesLoading.value = false
  }
}

const loadInstances = async () => {
  if (!selectedNodeId.value) return
  instLoading.value = true
  try {
    const d = await getNodeInstances(selectedNodeId.value)
    instances.value = d.instances || []
    loadRuleHits() // 加载规则命中率(规则活性分析),不阻塞实例展示
  } catch {
    ElMessage.error('加载实例失败')
  } finally {
    instLoading.value = false
  }
}

// 规则活性分析:加载节点规则命中率 + 死规则标记
const loadRuleHits = async () => {
  if (!selectedNodeId.value) return
  try {
    const d = await getNodeRuleHits(selectedNodeId.value)
    const m = {}
    for (const h of (d.hits || [])) {
      m[h.instance_id] = h
    }
    ruleHitsMap.value = m
  } catch {
    // 命中率加载失败不阻塞(可能 Agent 未上报)
  }
}

// 格式化命中率显示
const formatHits = (h) => {
  if (!h || !h.last_seen) return '未采集'
  return `${h.packets} 包 / ${formatBytes(h.bytes)}`
}
const formatBytes = (b) => {
  if (!b) return '0 B'
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  return (b / 1048576).toFixed(1) + ' MB'
}

const loadDeps = async () => {
  try {
    const [t, c, ag, mk] = await Promise.all([getTemplates(), getCustomChains(), getAddressGroups(), getMarks()])
    templates.value = t.templates || []
    customChains.value = c.custom_chains || c.chains || []
    addressGroups.value = ag.address_groups || []
    marks.value = mk.marks || []
  } catch {
    // 依赖加载失败不阻塞
  }
}

const selectNode = (n) => {
  selectedNodeId.value = n.id
  loadInstances()
}

// 流量预演(计划二):五元组仿真当前节点期望规则的命中路径
const simVisible = ref(false)
const simLoading = ref(false)
const simResult = ref(null)
const simForm = reactive({ direction: 'INPUT', source_ip: '', dest_ip: '', protocol: 'tcp', src_port: 0, dst_port: 8080 })

const openSimulate = () => {
  simForm.direction = 'INPUT'
  simForm.source_ip = ''
  simForm.dest_ip = ''
  simForm.protocol = 'tcp'
  simForm.src_port = 0
  simForm.dst_port = 8080
  simResult.value = null
  simVisible.value = true
}

const verdictTagType = (v) => ({ ACCEPT: 'success', DROP: 'danger', REJECT: 'warning', PASS: 'info' }[v] || 'info')

const handleSimulate = async () => {
  if (!selectedNodeId.value) return
  simLoading.value = true
  simResult.value = null
  try {
    const d = await simulateFlow({
      node_id: selectedNodeId.value,
      flow: { ...simForm },
    })
    simResult.value = d
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '预演失败')
  } finally {
    simLoading.value = false
  }
}

// 从模板实例化
const instantiateVisible = ref(false)
const instantiating = ref(false)
const instantiateForm = reactive({ template_id: null, name: '', apply: true, source: '', source_group: '' })
// 选中模板是否 MARK 白名单(无源骨架,实例化时需补源)
const selectedTpl = computed(() => templates.value.find((t) => t.id === instantiateForm.template_id))
const isMarkTpl = computed(() => selectedTpl.value?.action === 'MARK')
const openInstantiate = () => {
  instantiateForm.template_id = null
  instantiateForm.name = ''
  instantiateForm.apply = true
  instantiateForm.source = ''
  instantiateForm.source_group = ''
  instantiateVisible.value = true
}
const handleInstantiate = async () => {
  if (!instantiateForm.template_id) { ElMessage.warning('请选模板'); return }
  // MARK 白名单模板无源骨架,实例化时必须补源(实例层 requireMarkSource 校验)
  if (isMarkTpl.value && !instantiateForm.source && !instantiateForm.source_group) {
    ElMessage.warning('请填源地址或源地址组(白名单)')
    return
  }
  instantiating.value = true
  try {
    await createInstance(selectedNodeId.value, {
      template_id: instantiateForm.template_id,
      name: instantiateForm.name,
      apply: instantiateForm.apply,
      source: instantiateForm.source,
      source_group: instantiateForm.source_group,
    })
    ElMessage.success('已实例化' + (instantiateForm.apply ? '并下发' : ''))
    instantiateVisible.value = false
    loadInstances()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '实例化失败')
  } finally {
    instantiating.value = false
  }
}

// 新建/编辑策略(共用表单):isCreate 区分新建(POST 完整参数,template_id=0)与编辑(PUT 更新)
const formVisible = ref(false)
const savingInst = ref(false)
const isCreate = ref(false)
const defaultForm = () => ({
  template_id: 0, name: '', group_id: 0, direction: 'FORWARD', source: '', destination: '',
  source_group: '', destination_group: '', protocol: 'ANY',
  port_range: '', action: 'ACCEPT', mark: 0, nat_to: '',
  match_mark: 0, priority: 50, description: '', enabled: true, apply: false
})
const instForm = reactive(defaultForm())
// 动作切换时清理关联字段:MARK 不需要组/链,非 MARK 不需要方向
watch(() => instForm.action, (action) => {
  if (action === 'MARK') {
    instForm.group_id = 0
    if (!instForm.direction) instForm.direction = 'FORWARD'
  } else {
    instForm.direction = ''
  }
})
const openCreate = () => {
  isCreate.value = true
  Object.assign(instForm, defaultForm())
  instForm.direction = instForm.action === 'MARK' ? 'FORWARD' : ''
  formVisible.value = true
}
const openEditInst = (inst) => {
  isCreate.value = false
  Object.assign(instForm, defaultForm(), inst)
  formVisible.value = true
}
const saveInst = async () => {
  if (!instForm.name) { ElMessage.warning('请填实例名称'); return }
  // MARK 白名单拦截:方向+源地址组+端口+标记值;其他动作需选策略组
  if (instForm.action === 'MARK') {
    if (!instForm.source && !instForm.source_group) { ElMessage.warning('请填源地址或源地址组(白名单)'); return }
    if (!instForm.port_range) { ElMessage.warning('请填端口'); return }
    if (!instForm.mark) { ElMessage.warning('请选标记值'); return }
  } else {
    if (!instForm.group_id) { ElMessage.warning('请选策略组'); return }
  }
  // 匹配标记入口已移除(仅 MARK 打标保留),强制清零避免旧实例残留 match_mark
  instForm.match_mark = 0
  savingInst.value = true
  try {
    if (isCreate.value) {
      await createInstance(selectedNodeId.value, instForm)
      ElMessage.success('已新建' + (instForm.apply ? '并下发' : ''))
    } else {
      await updateInstance(instForm.id, instForm)
      ElMessage.success('已保存')
    }
    formVisible.value = false
    loadInstances()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '保存失败')
  } finally {
    savingInst.value = false
  }
}

const handleSync = async (inst) => {
  try {
    // 先调预览接口拿字段级 diff,展示"将覆盖什么"再确认(降低手动同步认知负担)
    let diffText = '将用模板最新参数覆盖此实例'
    try {
      const p = await syncInstancePreview(inst.id)
      const fields = p.fields || []
      if (fields.length) {
        diffText = '将覆盖以下字段:<br>' + fields
          .map((f) => `· ${f.label}: ${f.current || '(空)'} → ${f.template || '(空)'}`)
          .join('<br>')
      } else {
        diffText = '实例与模板当前参数一致,无需同步'
      }
    } catch { /* 预览失败不阻塞,仍可确认 */ }
    await ElMessageBox.confirm(`同步实例「${inst.name}」?<br>${diffText}`, '确认同步', {
      type: 'warning', dangerouslyUseHTMLString: true, confirmButtonText: '同步', cancelButtonText: '取消'
    })
    await syncInstance(inst.id)
    ElMessage.success('已同步')
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('同步失败')
  }
}

// 字段中文名映射:实例与模板参数 diff 的 tooltip 展示
const fieldLabels = { group_id: '所属策略组', direction: '流量方向', source: '源地址', destination: '目的地址', protocol: '协议', port_range: '端口', action: '动作', mark: '标记', nat_to: '转换目标', source_group: '源地址组', destination_group: '目的地址组', match_mark: '匹配标记', priority: '优先级' }
const driftFieldsText = (inst) => {
  const f = inst.deviated_fields || inst.drift_fields || []
  if (!f.length) return '与模板参数一致'
  return '与模板不一致: ' + f.map((x) => fieldLabels[x] || x).join('、')
}

// 批量同步:一键把当前节点所有漂移实例同步为模板最新参数
const syncingAll = ref(false)
const driftInstanceCount = computed(() => instances.value.filter((i) => i.drift).length)
const handleSyncAll = async () => {
  const n = driftInstanceCount.value
  if (!n) { ElMessage.info('没有待同步的漂移实例'); return }
  try {
    await ElMessageBox.confirm(`将把当前节点 ${n} 个漂移实例同步为模板最新参数. 手动修改过的实例参数将被覆盖, 同步后需重新下发生效.`, '确认批量同步', { type: 'warning', confirmButtonText: '同步', cancelButtonText: '取消' })
    syncingAll.value = true
    const d = await syncAllNode(selectedNodeId.value)
    ElMessage.success(`已同步 ${d.synced} 个实例, 跳过 ${d.skipped} 个`)
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.response?.data?.error || '批量同步失败')
  } finally {
    syncingAll.value = false
  }
}

const handleDeleteInst = async (inst) => {
  try {
    await ElMessageBox.confirm(`移除实例「${inst.name}」?若已下发将进入保护期,可回滚.`, '确认移除', { type: 'warning', confirmButtonText: '移除', cancelButtonText: '取消' })
    const data = await deleteInstance(inst.id)
    if (data && data.task_id) {
      // 202:节点有规则,已下发移除并进保护期,轮询终态
      ElMessage.info('已移除并进入保护期,可在保护期面板确认或回滚')
      const t = await pollTaskDone(data.task_id)
      if (t && t.status === 'failed') {
        ElMessage.error('移除下发失败,实例已恢复')
      }
      loadInstances()
      guard.refresh()
    } else {
      // 204:节点无规则,直接删除
      ElMessage.success('已移除')
      loadInstances()
    }
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.response?.data?.error || '移除失败')
  }
}

const handleDispatch = async () => {
  // 后端 dispatch 为全量同步语义(编译节点所有 enabled 实例,Agent 全量重建链)。
  // 无待变更时跳过,避免无意义的全量重建;有变更时提示全量对齐。
  const pending = instances.value.filter(i => i.enabled && !i.applied)
  const disabling = instances.value.filter(i => !i.enabled && i.applied)
  if (!pending.length && !disabling.length) {
    ElMessage.info('没有待下发的策略变更,节点已与配置对齐,无需下发')
    return
  }
  dispatching.value = true
  try {
    const d = await dispatchNode(selectedNodeId.value, { auto_approve: true })
    const taskID = d.tasks?.[0]?.id
    if (!taskID) { ElMessage.warning('未创建任务'); return }
    const t = await pollTaskDone(taskID)
    if (!t) { ElMessage.warning('下发超时,请稍后查看'); loadInstances(); guard.refresh(); return }
    if (t.status === 'confirm_wait' || t.status === 'confirmed') {
      ElMessage.success('已下发,进入保护期,请到顶部确认')
    } else {
      ElMessage.error('下发失败: ' + (t.message || t.status))
    }
    loadInstances()
    guard.refresh()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '下发失败')
  } finally {
    dispatching.value = false
  }
}

onMounted(async () => {
  await loadNodes()
  loadDeps()
  if (route.query.node) {
    const n = nodes.value.find((x) => x.id === route.query.node)
    if (n) selectNode(n)
    try {
      const d = await getTasks({ status: 'confirm_wait' })
      guardTask.value = (d.tasks || []).find((t) => t.node_id === route.query.node) || null
    } catch {}
  }
})

// 页面已加载时从保护期跳转也能选中节点 + 显示 banner
watch(() => route.query.node, async (nodeId) => {
  if (!nodeId) { guardTask.value = null; return }
  if (!nodes.value.length) return
  const n = nodes.value.find((x) => x.id === nodeId)
  if (n) selectNode(n)
  try {
    const d = await getTasks({ status: 'confirm_wait' })
    guardTask.value = (d.tasks || []).find((t) => t.node_id === nodeId) || null
  } catch {}
})
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.guard-banner { margin-bottom: 12px; cursor: pointer; font-weight: 500; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { font-size: 18px; font-weight: 600; color: var(--c-text-1, #1e293b); margin: 0; }
.np-body { min-height: 480px; }
.node-card, .inst-card { height: 100%; }
.empty-mini { text-align: center; color: var(--c-text-3); padding: 24px 0; font-size: 13px; }
.node-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; font-size: 13px; }
.node-item:hover { background: var(--c-surface-2, #f5f7fa); }
.node-item.active { background: var(--c-primary-soft, #e0f2fe); color: var(--c-primary, #2563eb); font-weight: 600; }
.node-ip { font-family: 'Courier New', monospace; }
.inst-head { display: flex; justify-content: space-between; align-items: center; }
.inst-actions { display: flex; gap: 8px; }
.inst-list { display: flex; flex-direction: column; gap: 10px; }
.inst-item { border: 1px solid var(--c-border); border-radius: 12px; padding: 14px 16px; background: var(--c-surface); box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.04); transition: box-shadow var(--transition), border-color var(--transition); }
.inst-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.08); border-color: var(--c-border-hover); }
.inst-item.drift { border-color: var(--c-warning); background: rgba(251,191,36,0.08); }
.inst-item.not-applied { border-left: 3px solid var(--c-warning); }
.inst-item.disabled { opacity: .55; border-left: 3px solid var(--c-danger); background: rgba(0,0,0,0.02); }
.inst-item.disabled .inst-name { text-decoration: line-through; color: var(--c-text-3); }
.inst-top { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
.inst-name { font-weight: 600; color: #1e293b; }
.inst-rule { display: flex; align-items: center; gap: 14px; font-size: 13px; color: var(--c-text-2); flex-wrap: wrap; }
.field .lbl { color: var(--c-text-3); margin-right: 4px; }
.action { margin-left: auto; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: var(--c-bg); }
.action.accept { color: #16a34a; background: #dcfce7; }
.action.drop { color: #dc2626; background: #fee2e2; }
.action.reject { color: #d97706; background: #fef3c7; }
.action.mark { color: #2563eb; background: #dbeafe; }
.inst-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--c-bg); }
.inst-cmd { margin-top: 8px; padding: 6px 8px; background: var(--c-bg); border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; }
.inst-cmd code { display: block; white-space: pre-wrap; word-break: break-all; color: var(--c-text-3); line-height: 1.6; }
.foot-left { display: flex; align-items: center; gap: 10px; }
.prio { font-size: 12px; color: var(--c-text-3); }
.hits { font-size: 12px; color: var(--c-text-3); }
.dead-filter { margin-left: 8px; }
.cmd-preview { margin-top: 12px; }
.cmd-preview-head { font-size: 12px; color: #64748b; margin-bottom: 6px; }
.cmd-preview-code { background: var(--c-surface); color: var(--c-text-1); padding: 10px; border-radius: 6px; font-size: 12px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; margin: 0; }
.cmd-mark { color: #60a5fa; }
.cmd-accept { color: #4ade80; }
.cmd-drop { color: #f87171; }
.actions { display: flex; gap: 4px; }
.form-row { display: flex; gap: 12px; }
.form-col { flex: 1; }
.form-hint { display: block; margin-top: -8px; padding-left: 90px; font-size: 12px; color: var(--c-text-3); }

/* 流量预演结果 */
.sim-result { margin-top: 12px; border: 1px solid var(--c-bg); border-radius: 6px; padding: 10px; background: var(--c-surface); }
.sim-verdict { font-size: 13px; color: var(--c-text-1); margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.sim-steps-title { font-size: 12px; color: var(--c-text-3); margin-bottom: 6px; }
.sim-steps { max-height: 240px; overflow-y: auto; }
.sim-step { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 4px 6px; border-radius: 4px; color: var(--c-text-3); font-family: 'Courier New', monospace; }
.sim-step.is-hit { background: rgba(74, 222, 128, 0.08); color: var(--c-text-1); }
.sim-idx { color: var(--c-text-3); width: 18px; flex-shrink: 0; }
.sim-chain { color: #60a5fa; }
.sim-action { flex-shrink: 0; }
.sim-action.hit { color: #4ade80; font-weight: 600; }
.sim-rule { flex: 1; }
.sim-note { color: #fbbf24; font-size: 11px; }
.sim-note-line { margin-top: 8px; font-size: 12px; color: var(--c-text-3); }
.sim-empty { font-size: 12px; color: var(--c-text-3); }
.verdict-accept { border-color: rgba(74, 222, 128, 0.5); }
.verdict-drop { border-color: rgba(248, 113, 113, 0.5); }
.verdict-reject { border-color: rgba(251, 191, 36, 0.5); }
</style>
