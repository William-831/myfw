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
                <el-button size="small" type="success" @click="handleDispatch" :disabled="!selectedNodeId || !instances.length" :loading="dispatching">下发节点</el-button>
              </div>
            </div>
          </template>
          <div v-if="!selectedNodeId" class="empty-mini">请选择左侧节点</div>
          <div v-else-if="!instances.length" class="empty-mini">该节点暂无策略实例,点"从模板实例化"添加</div>
          <div v-else class="inst-list">
            <div v-for="inst in instances" :key="inst.id" class="inst-item" :class="{ disabled: !inst.enabled, drift: inst.drift, 'not-applied': inst.enabled && !inst.applied }">
              <div class="inst-top">
                <span class="inst-name">{{ inst.name }}</span>
                <el-tag size="small" type="info">模板: {{ inst.template_name || '-' }}</el-tag>
                <el-tag v-if="inst.drift" size="small" type="warning" effect="dark">⚠ 模板已更新</el-tag>
                <el-tag v-if="inst.enabled && !inst.applied" size="small" type="warning" effect="dark">未下发</el-tag>
                <el-tag v-else-if="inst.enabled && inst.applied" size="small" type="success" effect="plain">已下发</el-tag>
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
                  <el-switch :model-value="inst.enabled" size="small" @change="(v) => toggleEnabled(inst, v)" />
                </div>
                <div class="actions">
                  <el-button size="small" text type="warning" @click="openEditInst(inst)">编辑参数</el-button>
                  <el-button v-if="inst.drift" size="small" text type="primary" @click="handleSync(inst)">同步模板</el-button>
                  <el-button size="small" text type="danger" @click="handleDeleteInst(inst)">移除</el-button>
                </div>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 从模板实例化 -->
    <el-dialog v-model="instantiateVisible" title="从模板实例化" width="480px">
      <el-form label-width="90px">
        <el-form-item label="选择模板">
          <el-select v-model="instantiateForm.template_id" placeholder="模板" style="width: 100%">
            <el-option v-for="t in templates" :key="t.id" :label="`${t.name} (${t.action}, ${t.protocol || 'ANY'})`" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="实例名称"><el-input v-model="instantiateForm.name" placeholder="空则用模板名" /></el-form-item>
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
            <el-option v-for="cc in customChains" :key="cc.id" :label="`MYFW-${cc.name} (${cc.parent})`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <div v-if="instForm.action !== 'MARK'" class="form-row">
          <el-form-item label="源地址" class="form-col"><el-input v-model="instForm.source" placeholder="空=任意" /></el-form-item>
          <el-form-item label="目标地址" class="form-col"><el-input v-model="instForm.destination" placeholder="空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="instForm.source_group" clearable placeholder="空=不匹配组" style="width: 100%">
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
          <el-select v-model="instForm.action" style="width: 100%"><el-option label="允许" value="ACCEPT" /><el-option label="丢弃" value="DROP" /><el-option label="拒绝" value="REJECT" /><el-option label="标记" value="MARK" /><el-option label="DNAT" value="DNAT" /><el-option label="SNAT" value="SNAT" /></el-select>
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
          <span class="form-hint">选方向+源地址组(白名单)+端口+标记值,自动生成:打标 -> 白名单放行 -> 其余丢弃</span>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'DNAT' || instForm.action === 'SNAT'" label="NAT 目标"><el-input v-model="instForm.nat_to" placeholder="如 1.2.3.4 或 1.2.3.4:8080" /></el-form-item>
        <div class="form-row">
          <el-form-item v-if="instForm.action !== 'MARK'" label="匹配标记" class="form-col">
            <el-select v-model="instForm.match_mark" clearable placeholder="0=不匹配" style="width: 100%">
              <el-option label="无" :value="0" />
              <el-option v-for="m in marks" :key="m.id" :label="`${m.name} (${m.value})`" :value="m.value" />
            </el-select>
          </el-form-item>
          <el-form-item label="优先级" class="form-col"><el-input-number v-model="instForm.priority" style="width: 100%" /></el-form-item>
        </div>
        <el-form-item label="描述"><el-input v-model="instForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="instForm.enabled" /></el-form-item>
        <el-form-item v-if="isCreate" label="立即应用"><el-switch v-model="instForm.apply" /></el-form-item>
      </el-form>
      <div class="cmd-preview">
        <div class="cmd-preview-head">命令预览(规则落 MYFW 自定义链,系统链已自动跳转)</div>
        <pre class="cmd-preview-code">{{ previewCommand }}</pre>
      </div>
      <template #footer>
        <el-button @click="formVisible = false">取消</el-button>
        <el-button type="primary" @click="saveInst" :loading="savingInst">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import ExpertMode from './ExpertMode.vue'
import { getNodes, getNodeInstances, createInstance, updateInstance, deleteInstance, syncInstance, dispatchNode, getTemplates, getCustomChains, getAddressGroups, getMarks } from '@/api'

const nodesLoading = ref(false)
const instLoading = ref(false)
const dispatching = ref(false)
const nodes = ref([])
const instances = ref([])
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

const getActionLabel = (a) => ({ ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '标记', DNAT: 'DNAT', SNAT: 'SNAT' }[a] || a || '-')

// MARK 联动放行组:仅列 FORWARD 父链的策略组(Docker 端口映射流量走 FORWARD)
const forwardGroups = computed(() => customChains.value.filter((c) => c.parent === 'MYFW-FORWARD'))

// 命令预览:根据实例表单拼接底层 iptables 命令,无感教学
const previewCommand = computed(() => {
  const f = instForm
  // MARK 白名单拦截:预览 3 条规则链(打标 + 白名单放行 + 兜底丢弃),落平台内置链
  if (f.action === 'MARK' && f.source_group && f.port_range) {
    const acl = f.direction === 'INPUT' ? 'MYFW-MARKACL-IN' : 'MYFW-MARKACL-FWD'
    const pp = f.protocol && f.protocol !== 'ANY' ? `-p ${f.protocol.toLowerCase()} --dport ${f.port_range}` : `--dport ${f.port_range}`
    const m = String(f.mark || 0)
    return [
      `iptables -t mangle -A MYFW-MARKMANGLE ${pp} -j MARK --set-mark ${m}`,
      `iptables -t filter -A ${acl} -m set --match-set ${f.source_group} src -m mark --mark ${m} -j ACCEPT`,
      `iptables -t filter -A ${acl} -m mark --mark ${m} -j DROP`,
    ].join('\n')
  }
  const cc = customChains.value.find(c => c.id === f.group_id)
  const table = cc?.table || 'filter'
  const chain = cc ? `MYFW-${cc.name}` : 'MYFW-INPUT'
  const parts = ['iptables', '-t', table, '-A', chain]
  if (f.source) parts.push('-s', f.source)
  if (f.destination) parts.push('-d', f.destination)
  if (f.source_group) parts.push('-m', 'set', '--match-set', f.source_group, 'src')
  if (f.destination_group) parts.push('-m', 'set', '--match-set', f.destination_group, 'dst')
  if (f.match_mark) parts.push('-m', 'mark', '--mark', String(f.match_mark))
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
  return parts.join(' ')
})

// 一键启停:切换实例 enabled(需重新下发节点才生效)
const toggleEnabled = async (inst, v) => {
  try {
    await updateInstance(inst.id, { ...inst, enabled: v })
    ElMessage.success(v ? '已启用,请下发节点生效' : '已禁用,请下发节点生效')
    loadInstances()
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
  } catch {
    ElMessage.error('加载实例失败')
  } finally {
    instLoading.value = false
  }
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

// 从模板实例化
const instantiateVisible = ref(false)
const instantiating = ref(false)
const instantiateForm = reactive({ template_id: null, name: '', apply: true })
const openInstantiate = () => {
  instantiateForm.template_id = null
  instantiateForm.name = ''
  instantiateForm.apply = true
  instantiateVisible.value = true
}
const handleInstantiate = async () => {
  if (!instantiateForm.template_id) { ElMessage.warning('请选模板'); return }
  instantiating.value = true
  try {
    await createInstance(selectedNodeId.value, { template_id: instantiateForm.template_id, name: instantiateForm.name, apply: instantiateForm.apply })
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
  name: '', group_id: null, direction: 'FORWARD', source: '', destination: '',
  source_group: '', destination_group: '', protocol: 'ANY',
  port_range: '', action: 'ACCEPT', mark: 0, nat_to: '',
  match_mark: 0, mark_acl_group_id: null, priority: 50, description: '', enabled: true, apply: false
})
const instForm = reactive(defaultForm())
const openCreate = () => {
  isCreate.value = true
  Object.assign(instForm, defaultForm())
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
    if (!instForm.source_group) { ElMessage.warning('请选源地址组(白名单)'); return }
    if (!instForm.port_range) { ElMessage.warning('请填端口'); return }
    if (!instForm.mark) { ElMessage.warning('请选标记值'); return }
  } else {
    if (!instForm.group_id) { ElMessage.warning('请选策略组'); return }
  }
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
    await ElMessageBox.confirm(`同步实例「${inst.name}」为模板最新参数?当前实例参数将被覆盖.`, '确认同步', { type: 'warning', confirmButtonText: '同步', cancelButtonText: '取消' })
    await syncInstance(inst.id)
    ElMessage.success('已同步')
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('同步失败')
  }
}

const handleDeleteInst = async (inst) => {
  try {
    await ElMessageBox.confirm(`移除实例「${inst.name}」?节点规则需重新下发才生效.`, '确认移除', { type: 'warning', confirmButtonText: '移除', cancelButtonText: '取消' })
    await deleteInstance(inst.id)
    ElMessage.success('已移除')
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('移除失败')
  }
}

const handleDispatch = async () => {
  dispatching.value = true
  try {
    await dispatchNode(selectedNodeId.value, { auto_approve: true })
    ElMessage.success('已下发,进入保护期,请到顶部确认')
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '下发失败')
  } finally {
    dispatching.value = false
  }
}

onMounted(() => {
  loadNodes()
  loadDeps()
})
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { font-size: 18px; font-weight: 600; color: var(--c-text-1, #1e293b); margin: 0; }
.np-body { min-height: 480px; }
.node-card, .inst-card { height: 100%; }
.empty-mini { text-align: center; color: #94a3b8; padding: 24px 0; font-size: 13px; }
.node-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; font-size: 13px; }
.node-item:hover { background: var(--c-surface-2, #f5f7fa); }
.node-item.active { background: var(--c-primary-soft, #e0f2fe); color: var(--c-primary, #2563eb); font-weight: 600; }
.node-ip { font-family: 'Courier New', monospace; }
.inst-head { display: flex; justify-content: space-between; align-items: center; }
.inst-actions { display: flex; gap: 8px; }
.inst-list { display: flex; flex-direction: column; gap: 10px; }
.inst-item { border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; }
.inst-item.drift { border-color: #f59e0b; background: #fffbeb; }
.inst-item.not-applied { border-left: 3px solid #f59e0b; }
.inst-item.disabled { opacity: .6; }
.inst-top { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
.inst-name { font-weight: 600; color: #1e293b; }
.inst-rule { display: flex; align-items: center; gap: 14px; font-size: 13px; color: #475569; flex-wrap: wrap; }
.field .lbl { color: #94a3b8; margin-right: 4px; }
.action { margin-left: auto; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #f1f5f9; }
.action.accept { color: #16a34a; background: #dcfce7; }
.action.drop { color: #dc2626; background: #fee2e2; }
.action.reject { color: #d97706; background: #fef3c7; }
.action.mark { color: #2563eb; background: #dbeafe; }
.inst-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid #f1f5f9; }
.foot-left { display: flex; align-items: center; gap: 10px; }
.prio { font-size: 12px; color: #94a3b8; }
.cmd-preview { margin-top: 12px; }
.cmd-preview-head { font-size: 12px; color: #64748b; margin-bottom: 6px; }
.cmd-preview-code { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 6px; font-size: 12px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; margin: 0; }
.actions { display: flex; gap: 4px; }
.form-row { display: flex; gap: 12px; }
.form-col { flex: 1; }
.form-hint { display: block; margin-top: -8px; padding-left: 90px; font-size: 12px; color: #94a3b8; }
</style>
