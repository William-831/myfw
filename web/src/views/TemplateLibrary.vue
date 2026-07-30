<template>
  <div class="tpl-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">策略模板库</h2>
        <el-tag size="small" type="info">{{ templates.length }} 个模板</el-tag>
      </div>
      <div class="header-right">
        <el-button type="primary" @click="openAdd"><el-icon><Plus /></el-icon>新增模板</el-button>
      </div>
    </div>

    <div v-loading="loading" class="tpl-grid">
      <div v-if="!templates.length && !loading" class="empty"><el-empty description="暂无模板" /></div>
      <div v-for="t in templates" :key="t.id" class="tpl-card" :class="{ disabled: !t.enabled }">
        <div class="card-head">
          <span class="tpl-name">{{ t.name }}</span>
          <el-tag v-if="t.group_id" size="small" type="warning">{{ getGroupName(t.group_id) }}</el-tag>
          <el-tag v-else size="small" type="danger">未归组</el-tag>
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
          <div class="actions">
            <el-button size="small" text type="warning" @click="openEdit(t)">编辑</el-button>
            <el-button size="small" text type="danger" @click="handleDelete(t)">删除</el-button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="640px" :close-on-click-modal="false">
      <el-form :model="form" ref="formRef" label-width="90px">
        <el-form-item label="模板名称" prop="name" :rules="[{ required: true, message: '必填' }]">
          <el-input v-model="form.name" placeholder="如: 允许SSH" />
        </el-form-item>
        <el-form-item label="所属组" prop="group_id" :rules="[{ required: true, message: '必选' }]">
          <el-select v-model="form.group_id" placeholder="策略组(继承方向/子链)" style="width: 100%">
            <el-option v-for="cc in customChains" :key="cc.id" :label="`MYFW-${cc.name} (${cc.parent}, #${cc.priority ?? 50})`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源地址" class="form-col"><el-input v-model="form.source" placeholder="IP/CIDR,空=任意" /></el-form-item>
          <el-form-item label="目标地址" class="form-col"><el-input v-model="form.destination" placeholder="IP/CIDR,空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="form.source_group" clearable placeholder="引用地址组">
              <el-option v-for="g in addressGroups" :key="g.id" :label="`${g.name} (${g.kind})`" :value="g.name" />
            </el-select>
          </el-form-item>
          <el-form-item label="目的地址组" class="form-col">
            <el-select v-model="form.destination_group" clearable placeholder="引用地址组">
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
            <el-option label="允许 ACCEPT" value="ACCEPT" /><el-option label="丢弃 DROP" value="DROP" /><el-option label="拒绝 REJECT" value="REJECT" /><el-option label="标记 MARK" value="MARK" /><el-option label="DNAT" value="DNAT" /><el-option label="SNAT" value="SNAT" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.action === 'DNAT' || form.action === 'SNAT'" label="NAT目标"><el-input v-model="form.nat_to" placeholder="192.168.1.100:8080" /></el-form-item>
        <el-form-item v-if="form.action === 'MARK'" label="标记值">
          <el-select v-model="form.mark" style="width: 200px"><el-option label="dev (15)" :value="15" /><el-option label="ops (255)" :value="255" /></el-select>
        </el-form-item>
        <el-form-item v-if="form.action === 'MARK' && form.source_group" label="放行组">
          <el-select v-model="form.mark_acl_group_id" placeholder="filter 组" style="width: 100%">
            <el-option v-for="cc in aclGroupOptions" :key="cc.id" :label="`MYFW-${cc.name} (${cc.parent})`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="form.priority" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="save" :loading="saving">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { getTemplates, createTemplate, updateTemplate, deleteTemplate, getCustomChains, getAddressGroups } from '@/api'

const loading = ref(false)
const saving = ref(false)
const templates = ref([])
const customChains = ref([])
const addressGroups = ref([])
// MARK 联动放行组候选:仅 filter 表的组
const aclGroupOptions = computed(() => (customChains.value || []).filter(c => ['MYFW-INPUT', 'MYFW-OUTPUT', 'MYFW-FORWARD'].includes(c.parent)))

const dialogVisible = ref(false)
const dialogTitle = ref('新增模板')
const formRef = ref(null)
const editingId = ref(null)
const form = reactive(emptyForm())

function emptyForm() {
  return { name: '', group_id: null, source: '', destination: '', protocol: 'ANY', port_range: '', action: 'ACCEPT', mark: 0, nat_to: '', source_group: '', destination_group: '', match_mark: 0, mark_acl_group_id: null, priority: 10, description: '', enabled: true }
}

const getGroupName = (id) => { const c = customChains.value.find(x => x.id === id); return c ? c.name : '-' }
const getActionLabel = (a) => ({ ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '标记', DNAT: 'DNAT', SNAT: 'SNAT' }[a] || a || '-')

const loadTemplates = async () => {
  loading.value = true
  try {
    const d = await getTemplates()
    templates.value = d.templates || []
  } catch {
    ElMessage.error('加载模板失败')
  } finally {
    loading.value = false
  }
}

const loadDeps = async () => {
  try {
    const [c, g] = await Promise.all([getCustomChains(), getAddressGroups()])
    customChains.value = c.custom_chains || c.chains || []
    addressGroups.value = g.address_groups || g.groups || []
  } catch {
    // 依赖加载失败不阻塞模板展示
  }
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

onMounted(() => {
  loadDeps()
  loadTemplates()
})
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { font-size: 18px; font-weight: 600; color: var(--c-text-1, #1e293b); margin: 0; }
.tpl-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; }
.empty { grid-column: 1 / -1; }
.tpl-card { border: 1px solid var(--c-border, #e2e8f0); border-radius: 10px; padding: 14px; background: var(--c-surface, #fff); transition: box-shadow .2s; }
.tpl-card:hover { box-shadow: 0 2px 12px rgba(0,0,0,.08); }
.tpl-card.disabled { opacity: .6; }
.card-head { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.tpl-name { font-weight: 600; color: #1e293b; }
.card-rule { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; font-size: 13px; color: #475569; }
.field .lbl { color: #94a3b8; margin-right: 4px; }
.action { margin-left: auto; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #f1f5f9; }
.action.accept { color: #16a34a; background: #dcfce7; }
.action.drop { color: #dc2626; background: #fee2e2; }
.action.reject { color: #d97706; background: #fef3c7; }
.action.mark { color: #2563eb; background: #dbeafe; }
.card-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid #f1f5f9; }
.prio { font-size: 12px; color: #94a3b8; }
.actions { display: flex; gap: 4px; }
.form-row { display: flex; gap: 12px; }
.form-col { flex: 1; }
</style>
