<template>
  <div class="tpl-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">策略模板库</h2>
        <el-tag size="small" type="info">{{ templates.length }} 个模板</el-tag>
          <el-button text :icon="allExpanded ? Fold : Expand" size="small" @click="allExpanded ? collapseAll() : expandAll()" style="margin-left: 6px; padding: 0 8px;">
            {{ allExpanded ? "折叠" : "展开" }}
          </el-button>
        </div>
      <div class="header-right">
        <el-button @click="openMarkManager">标记管理</el-button>
        <el-switch v-model="multiSelect" active-text="多选" inline-prompt />
        <el-button v-if="multiSelect && selected.length" type="warning" @click="openMultiInst">实例化到节点 ({{ selected.length }})</el-button>
        <el-button type="primary" @click="openAdd"><el-icon><Plus /></el-icon>新增模板</el-button>
        <el-button @click="handleExport">导出</el-button>
        <el-button @click="triggerImport">导入</el-button>
        <input ref="fileInput" type="file" accept=".json" style="display:none" @change="handleImport" />
      </div>
    </div>

    <!-- 分类展示:按策略组折叠 -->
    <el-collapse v-model="openedGroups" v-loading="loading" class="tpl-collapse">
      <div v-if="!templates.length && !loading" class="empty"><el-empty description="暂无模板" /></div>
      <el-collapse-item v-for="g in groupedTemplates" :key="g.key" :name="g.key">
        <template #title>
          <span class="group-title">{{ g.label }}</span>
          <el-tag size="small" type="info" class="group-count">{{ g.templates.length }} 个</el-tag>
        </template>
        <div class="tpl-grid">
          <div
            v-for="t in g.templates"
            :key="t.id"
            class="tpl-card"
            :class="{ disabled: !t.enabled, selected: selected.includes(t.id) }"
            @click="onCardClick(t)"
          >
            <el-checkbox
              v-if="multiSelect"
              :model-value="selected.includes(t.id)"
              class="card-checkbox"
              @change="(v) => toggleSelect(t.id, v)"
              @click.stop
            />
            <div class="card-head">
              <span class="tpl-name">{{ t.name }}</span>
              <el-tag :type="t.enabled ? 'success' : 'info'" size="small">{{ t.enabled ? '启用' : '禁用' }}</el-tag>
            </div>
            <div class="card-rule">
              <span class="field"><span class="lbl">协议</span>{{ t.protocol || 'ANY' }}</span>
              <span class="field"><span class="lbl">端口</span>{{ t.port_range || '任意' }}</span>
              <span class="action" :class="t.action ? t.action.toLowerCase() : ''">{{ getActionLabel(t.action) }}</span>
            </div>
            <div class="card-rule">
              <span class="field"><span class="lbl">源</span>{{ t.source || '任意' }}</span>
              <span class="field"><span class="lbl">目的</span>{{ t.destination || '任意' }}</span>
            </div>
            <div class="card-foot">
              <span class="prio">优先级 #{{ t.priority }}</span>
              <div class="actions" v-if="!multiSelect">
                <el-button size="small" text type="warning" @click.stop="openEdit(t)">编辑</el-button>
                <el-button size="small" text type="danger" @click.stop="handleDelete(t)">删除</el-button>
              </div>
            </div>
          </div>
        </div>
      </el-collapse-item>
    </el-collapse>

    <!-- 新增/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="640px" :close-on-click-modal="false">
      <el-form :model="form" ref="formRef" label-width="90px">
        <el-form-item label="模板名称" prop="name" :rules="[{ required: true, message: '必填' }]">
          <el-input v-model="form.name" placeholder="如: 允许SSH" />
        </el-form-item>
        <el-form-item label="所属组" prop="group_id" :rules="[{ required: true, message: '必选' }]">
          <el-select v-model="form.group_id" placeholder="策略组(继承方向/子链)" style="width: 100%">
            <el-option v-for="cc in customChains" :key="cc.id" :label="`${cc.name} - ${cc.description || cc.parent}`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源地址" class="form-col"><el-input v-model="form.source" placeholder="IP/CIDR,空=任意" /></el-form-item>
          <el-form-item label="目标地址" class="form-col"><el-input v-model="form.destination" placeholder="IP/CIDR,空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="form.source_group" clearable placeholder="引用地址组" style="width: 100%">
              <el-option v-for="g in addressGroups" :key="g.id" :label="`${g.name} (${g.kind})`" :value="g.name" />
            </el-select>
          </el-form-item>
          <el-form-item label="目的地址组" class="form-col">
            <el-select v-model="form.destination_group" clearable placeholder="引用地址组" style="width: 100%">
              <el-option v-for="g in addressGroups" :key="g.id" :label="`${g.name} (${g.kind})`" :value="g.name" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="协议" class="form-col">
            <el-select v-model="form.protocol" style="width: 100%">
              <el-option label="任意" value="ANY" /><el-option label="TCP" value="TCP" /><el-option label="UDP" value="UDP" /><el-option label="ICMP" value="ICMP" />
            </el-select>
          </el-form-item>
          <el-form-item label="端口范围" class="form-col"><el-input v-model="form.port_range" placeholder="22 或 80-8080" /></el-form-item>
        </div>
        <el-form-item label="动作">
          <el-select v-model="form.action" style="width: 100%">
            <el-option label="允许 ACCEPT" value="ACCEPT" /><el-option label="丢弃 DROP" value="DROP" /><el-option label="拒绝 REJECT" value="REJECT" /><el-option label="标记 MARK" value="MARK" /><el-option label="目的转换 DNAT" value="DNAT" /><el-option label="源转换 SNAT" value="SNAT" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.action === 'DNAT' || form.action === 'SNAT'" label="NAT目标"><el-input v-model="form.nat_to" placeholder="192.168.1.100:8080" /></el-form-item>
        <el-form-item v-if="form.action === 'MARK'" label="标记值">
          <el-select v-model="form.mark" style="width: 100%" placeholder="选标记(标记管理中维护)">
            <el-option v-for="m in marks" :key="m.id" :label="`${m.name} (${m.value})`" :value="m.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="form.priority" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <div class="cmd-preview">
        <div class="cmd-preview-head">命令预览(规则落 MYFW 自定义链)</div>
        <pre class="cmd-preview-code">{{ previewCommand }}</pre>
      </div>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="save" :loading="saving">确定</el-button>
      </template>
    </el-dialog>

    <!-- 标记管理抽屉 -->
    <el-drawer v-model="markDrawerVisible" title="标记管理" size="440px">
      <div class="mark-form">
        <el-input v-model="markForm.name" placeholder="标记名(如 dev)" style="width: 130px" />
        <el-input-number v-model="markForm.value" :min="0" :controls="false" placeholder="标记值" style="width: 120px" />
        <el-input v-model="markForm.description" placeholder="描述(可选)" style="flex: 1" />
        <el-button type="primary" size="small" @click="saveMark">{{ markEditingId ? '更新' : '添加' }}</el-button>
        <el-button v-if="markEditingId" size="small" @click="cancelMarkEdit">取消</el-button>
      </div>
      <div class="mark-list">
        <div v-for="m in marks" :key="m.id" class="mark-item">
          <span class="mark-name">{{ m.name }}</span>
          <el-tag size="small" type="warning">{{ m.value }}</el-tag>
          <span class="mark-desc">{{ m.description || '-' }}</span>
          <div class="mark-actions">
            <el-button size="small" text type="warning" @click="editMark(m)">编辑</el-button>
            <el-button size="small" text type="danger" @click="removeMark(m)">删除</el-button>
          </div>
        </div>
        <el-empty v-if="!marks.length" description="暂无标记,新增一个" :image-size="50" />
      </div>
    </el-drawer>

    <!-- 多选实例化到节点 -->
    <el-dialog v-model="multiInstVisible" title="批量实例化到节点" width="440px">
      <el-form label-width="90px">
        <el-form-item label="选中模板">
          <div class="multi-tags">
            <el-tag v-for="id in selected" :key="id" size="small" closable @close="toggleSelect(id, false)">{{ tplName(id) }}</el-tag>
          </div>
        </el-form-item>
        <el-form-item label="目标节点">
          <el-select v-model="multiInstNode" placeholder="选节点" style="width: 100%">
            <el-option v-for="n in nodes" :key="n.id" :label="n.ip || n.hostname || n.id.slice(0, 12)" :value="n.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="立即应用"><el-switch v-model="multiInstApply" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="multiInstVisible = false">取消</el-button>
        <el-button type="primary" @click="handleMultiInst" :loading="multiInstLoading">实例化</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Expand, Fold } from '@element-plus/icons-vue'
import {
  getTemplates, createTemplate, updateTemplate, deleteTemplate,
  getCustomChains, getAddressGroups, getNodes, createInstance,
  getMarks, createMark, updateMark, deleteMark,
  exportTemplates, importTemplates
} from '@/api'

const loading = ref(false)
const saving = ref(false)
const templates = ref([])
const customChains = ref([])
const addressGroups = ref([])
const marks = ref([])
const nodes = ref([])

// 多选
const multiSelect = ref(false)
const selected = ref([])

// 分类折叠:默认全展开
const openedGroups = ref([])

const dialogVisible = ref(false)
const dialogTitle = ref('新增模板')
const editingId = ref(null)
const form = reactive(emptyForm())

function emptyForm() {
  return { name: '', group_id: null, source: '', destination: '', protocol: 'ANY', port_range: '', action: 'ACCEPT', mark: 0, nat_to: '', source_group: '', destination_group: '', match_mark: 0, priority: 10, description: '', enabled: true }
}

const getActionLabel = (a) => ({ ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '标记', DNAT: 'DNAT', SNAT: 'SNAT' }[a] || a || '-')
const tplName = (id) => templates.value.find((t) => t.id === id)?.name || `#${id}`

// 按策略组分类(未归组单独一区)
const groupedTemplates = computed(() => {
  const byGroup = {}
  const ungrouped = []
  for (const t of templates.value) {
    if (t.group_id) {
      ;(byGroup[t.group_id] ||= []).push(t)
    } else {
      ungrouped.push(t)
    }
  }
  const groups = []
  for (const gid of Object.keys(byGroup)) {
    const cc = customChains.value.find((c) => c.id === Number(gid))
    groups.push({ key: 'g' + gid, label: cc ? `${cc.name} - ${cc.description || cc.parent}` : `组#${gid}`, templates: byGroup[gid] })
  }
  if (ungrouped.length) groups.push({ key: 'ungrouped', label: '未归组', templates: ungrouped })
  return groups
})

// 命令预览:基于表单拼接底层 iptables 命令
const previewCommand = computed(() => {
  const f = form
  const cc = customChains.value.find((c) => c.id === f.group_id)
  const table = cc?.table || 'filter'
  const chain = cc ? `MYFW-${cc.name}` : 'MYFW-INPUT'
  const parts = ['iptables', '-t', table, '-A', chain]
  if (f.source) parts.push('-s', f.source)
  if (f.destination) parts.push('-d', f.destination)
  if (f.source_group) parts.push('-m', 'set', '--match-set', f.source_group, 'src')
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
  return parts.join(' ')
})

const loadTemplates = async () => {
  loading.value = true
  try {
    const d = await getTemplates()
    templates.value = d.templates || []
    // 默认全展开分组
    openedGroups.value = groupedTemplates.value.map((g) => g.key)
  } catch {
    ElMessage.error('加载模板失败')
  } finally {
    loading.value = false
  }
}

const loadDeps = async () => {
  try {
    const [c, g, m, n] = await Promise.all([getCustomChains(), getAddressGroups(), getMarks(), getNodes()])
    customChains.value = c.custom_chains || c.chains || []
    addressGroups.value = g.address_groups || g.groups || []
    marks.value = m.marks || []
    nodes.value = (n.nodes || []).filter((x) => x.status === 'ACTIVE')
  } catch {
    // 依赖加载失败不阻塞模板展示
  }
}

const expandAll = () => { openedGroups.value = groupedTemplates.value.map((g) => g.key) }
const collapseAll = () => { openedGroups.value = [] }
const allExpanded = computed(() => openedGroups.value.length === groupedTemplates.value.length)

const onCardClick = (t) => {
  if (multiSelect.value) toggleSelect(t.id, !selected.value.includes(t.id))
}
const toggleSelect = (id, v) => {
  const i = selected.value.indexOf(id)
  if (v && i < 0) selected.value.push(id)
  if (!v && i >= 0) selected.value.splice(i, 1)
}

const openAdd = () => {
  Object.assign(form, emptyForm())
  editingId.value = null
  dialogTitle.value = '新增模板'
  dialogVisible.value = true
}
const openEdit = (t) => {
  Object.assign(form, t)
  editingId.value = t.id
  dialogTitle.value = '编辑模板'
  dialogVisible.value = true
}

const save = async () => {
  if (!form.name) { ElMessage.warning('请填模板名称'); return }
  if (!form.group_id) { ElMessage.warning('请选所属组'); return }
  saving.value = true
  try {
    if (editingId.value) {
      await updateTemplate(editingId.value, form)
    } else {
      await createTemplate(form)
    }
    ElMessage.success('已保存')
    dialogVisible.value = false
    loadTemplates()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

const handleDelete = async (t) => {
  try {
    await ElMessageBox.confirm(`删除模板「${t.name}」?已实例化的节点不受影响(实例独立保存参数).`, '确认删除', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
    await deleteTemplate(t.id)
    ElMessage.success('已删除')
    loadTemplates()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.response?.data?.error || '删除失败')
  }
}

// --- 标记管理 ---
const markDrawerVisible = ref(false)
const markEditingId = ref(null)
const markForm = reactive({ name: '', value: 0, description: '' })
const openMarkManager = () => { markDrawerVisible.value = true }

// 模板导出
const handleExport = async () => {
  try {
    const res = await exportTemplates()
    const blob = new Blob([JSON.stringify(res.bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `templates-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
    ElMessage.success('导出成功')
  } catch (e) {
    ElMessage.error('导出失败: ' + (e.response?.data?.error || e.message))
  }
}

// 模板导入：触发文件选择
const fileInput = ref(null)
const triggerImport = () => { fileInput.value?.click() }

// 模板导入：读取文件并上传
const handleImport = async (e) => {
  const file = e.target.files?.[0]
  if (!file) return
  try {
    const text = await file.text()
    let bundle
    try { bundle = JSON.parse(text) } catch { throw new Error('JSON 解析失败') }
    // 选择策略
    const { action } = await ElMessageBox({
      title: '导入确认',
      message: `将导入 ${bundle.marks?.length||0} 个标记、${bundle.custom_chains?.length||0} 个策略组、${bundle.templates?.length||0} 个模板。冲突策略？`,
      confirmButtonText: '跳过已存在',
      cancelButtonText: '覆盖已存在',
      showCancelButton: true,
      distinguishCancelAndClose: true,
      type: 'info',
    }).catch(act => ({ action: act }))
    const policy = action === 'cancel' ? 'overwrite' : 'skip'
    const res = await importTemplates({ policy, bundle })
    ElMessage.success(`导入完成: ${res.marks_created||0} 标记, ${res.chains_created||0} 策略组, ${res.templates_created||0} 模板`)
    await loadTemplates()
  } catch (e) {
    if (e === 'cancel' || e?.action === 'close') return
    ElMessage.error('导入失败: ' + (e.response?.data?.error || e.message || '未知错误'))
  }
  e.target.value = ''
}
const editMark = (m) => {
  markEditingId.value = m.id
  Object.assign(markForm, { name: m.name, value: m.value, description: m.description || '' })
}
const cancelMarkEdit = () => {
  markEditingId.value = null
  Object.assign(markForm, { name: '', value: 0, description: '' })
}
const saveMark = async () => {
  if (!markForm.name) { ElMessage.warning('请填标记名'); return }
  try {
    if (markEditingId.value) {
      await updateMark(markEditingId.value, markForm)
      ElMessage.success('已更新')
    } else {
      await createMark(markForm)
      ElMessage.success('已添加')
    }
    cancelMarkEdit()
    const d = await getMarks()
    marks.value = d.marks || []
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '保存失败')
  }
}
const removeMark = async (m) => {
  try {
    await ElMessageBox.confirm(`删除标记「${m.name}」?`, '确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
    await deleteMark(m.id)
    ElMessage.success('已删除')
    const d = await getMarks()
    marks.value = d.marks || []
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('删除失败')
  }
}

// --- 多选实例化 ---
const multiInstVisible = ref(false)
const multiInstNode = ref('')
const multiInstApply = ref(false)
const multiInstLoading = ref(false)
const openMultiInst = () => {
  multiInstNode.value = ''
  multiInstApply.value = false
  multiInstVisible.value = true
}
const handleMultiInst = async () => {
  if (!multiInstNode.value) { ElMessage.warning('请选节点'); return }
  multiInstLoading.value = true
  let ok = 0
  let fail = 0
  try {
    for (const id of selected.value) {
      try {
        await createInstance(multiInstNode.value, { template_id: id, apply: multiInstApply.value })
        ok++
      } catch {
        fail++
      }
    }
    ElMessage.success(`已实例化 ${ok} 个模板${fail ? `,失败 ${fail}` : ''}${multiInstApply.value ? '并下发' : ''}`)
    multiInstVisible.value = false
    selected.value = []
    multiSelect.value = false
  } catch (e) {
    ElMessage.error('实例化失败')
  } finally {
    multiInstLoading.value = false
  }
}

onMounted(() => {
  loadDeps()
  loadTemplates()
})
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.header-right { display: flex; align-items: center; gap: 12px; }
.fold-group { margin-right: 2px; }
.fold-group .el-button { padding: 0 11px; }
.page-title { font-size: 18px; font-weight: 600; color: var(--c-text-1, #1e293b); margin: 0; }

.tpl-collapse { border: none; }
.tpl-collapse :deep(.el-collapse-item__header) { font-weight: 600; font-size: 15px; color: var(--c-text-1, #1e293b); border: none; padding: 4px 0; }
.tpl-collapse :deep(.el-collapse-item__wrap) { border: none; }
.tpl-collapse :deep(.el-collapse-item__content) { padding-bottom: 12px; }
.group-title { margin-right: 10px; }
.group-count { margin-left: 4px; }
.empty { padding: 40px 0; }

.tpl-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; padding: 4px 0; }
.tpl-card { position: relative; border: 1px solid var(--c-border, var(--c-text-1)); border-radius: 16px; padding: 16px; background: var(--c-surface, #fff); transition: transform .2s ease, box-shadow .2s ease, border-color .2s; cursor: pointer; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
.tpl-card:hover { box-shadow: 0 8px 24px rgba(0,0,0,.08); transform: translateY(-2px); }
.tpl-card.disabled { opacity: .55; }
.tpl-card.selected { border-color: var(--c-primary, #4f46e5); box-shadow: 0 0 0 2px var(--c-primary-soft, rgba(79,70,229,.1)); }
.card-checkbox { position: absolute; top: 12px; right: 12px; }
.card-head { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.tpl-name { font-weight: 600; font-size: 15px; color: #1e293b; letter-spacing: .01em; }
.card-rule { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; font-size: 13px; color: var(--c-text-2); }
.field .lbl { color: var(--c-text-3); margin-right: 4px; }
.action { margin-left: auto; padding: 3px 10px; border-radius: 8px; font-size: 12px; font-weight: 600; background: var(--c-bg); }
.action.accept { color: #16a34a; background: #dcfce7; }
.action.drop { color: #dc2626; background: #fee2e2; }
.action.reject { color: #d97706; background: #fef3c7; }
.action.mark { color: #2563eb; background: #dbeafe; }
.card-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--c-bg); }
.prio { font-size: 12px; color: var(--c-text-3); }
.actions { display: flex; gap: 4px; }

.form-row { display: flex; gap: 12px; }
.form-col { flex: 1; }
.cmd-preview { margin-top: 8px; }
.cmd-preview-head { font-size: 12px; color: #64748b; margin-bottom: 6px; }
.cmd-preview-code { background: var(--c-surface); color: var(--c-text-1); padding: 10px; border-radius: 6px; font-size: 12px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; margin: 0; }

.mark-form { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.mark-list { display: flex; flex-direction: column; gap: 8px; }
.mark-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border: 1px solid var(--c-border, var(--c-text-1)); border-radius: 6px; font-size: 13px; }
.mark-name { font-weight: 600; color: var(--c-text-1, #1e293b); min-width: 60px; }
.mark-desc { color: var(--c-text-3); flex: 1; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mark-actions { display: flex; gap: 4px; }

.multi-tags { display: flex; flex-wrap: wrap; gap: 6px; }
</style>
