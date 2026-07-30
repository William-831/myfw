<template>
  <div class="cc-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">策略组</h2>
        <el-tag size="small" type="info">{{ chains.length }} 个</el-tag>
      </div>
      <el-button type="primary" @click="openAdd"><el-icon><Plus /></el-icon>新增策略组</el-button>
    </div>

    <el-alert type="info" :closable="false" class="tip">
      策略组对应底层自定义子链 MYFW-&lt;name&gt;,承载钩子方向与全局优先级。父链按组优先级顺序 jump 到各子链(基础设施优化规则 + 业务调度),具体规则全部落于子链。条目归属某组后自动继承方向,只需填源/目的/协议/端口/动作。
    </el-alert>

    <el-table :data="chains" v-loading="loading" stripe>
      <el-table-column label="名称" width="170">
        <template #default="{ row }"><span class="mono">MYFW-{{ row.name }}</span></template>
      </el-table-column>
      <el-table-column label="钩子方向" width="160" prop="parent" />
      <el-table-column label="优先级" width="90" prop="priority" />
      <el-table-column label="表" width="90" prop="table" />
      <el-table-column label="启用" width="80">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="描述" prop="description" min-width="180" show-overflow-tooltip />
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button size="small" text type="warning" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" text type="danger" @click="handleDelete(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="520px" :close-on-click-modal="false">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="90px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="如 business / ops-team(节点链 MYFW-<name>)" />
        </el-form-item>
        <el-form-item label="钩子方向" prop="parent">
          <el-select v-model="form.parent" style="width: 100%" @change="onParentChange">
            <el-option v-for="p in parentOptions" :key="p.value" :label="p.value" :value="p.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="全局优先级" prop="priority">
          <el-slider v-model="form.priority" :min="1" :max="100" :step="1" show-input />
          <span class="form-hint">父链中 jump 到本子链的顺序,值小排前</span>
        </el-form-item>
        <el-form-item label="表">
          <el-input v-model="form.table" disabled />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <div class="cmd-preview">
        <div class="cmd-preview-head">命令预览</div>
        <pre class="cmd-preview-code">{{ previewCmd }}</pre>
      </div>
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
import { getCustomChains, createCustomChain, updateCustomChain, deleteCustomChain } from '@/api'

const loading = ref(false)
const saving = ref(false)
const chains = ref([])
const dialogVisible = ref(false)
const dialogTitle = ref('新增策略组')
const formRef = ref(null)
const editingId = ref(null)

// 钩子方向(父链)白名单:父链 -> 所属表
const parentOptions = [
  { value: 'MYFW-INPUT', table: 'filter' },
  { value: 'MYFW-OUTPUT', table: 'filter' },
  { value: 'MYFW-FORWARD', table: 'filter' },
  { value: 'MYFW-PREROUTING', table: 'nat' },
  { value: 'MYFW-POSTROUTING', table: 'nat' },
  { value: 'MYFW-MANGLE', table: 'mangle' }
]

const form = reactive({ name: '', parent: 'MYFW-INPUT', table: 'filter', priority: 50, description: '', enabled: true })
const rules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  parent: [{ required: true, message: '请选择钩子方向', trigger: 'change' }]
}

const onParentChange = (v) => {
  const p = parentOptions.find(x => x.value === v)
  form.table = p ? p.table : 'filter'
}

// 命令预览:复刻后端 iptables driver 的子链创建/父链 jump 逻辑
const previewCmd = computed(() => {
  const name = `MYFW-${form.name || '<name>'}`
  return [
    '# 创建子链(策略组)',
    `iptables -t ${form.table} -N ${name}`,
    '',
    `# 父链按组优先级顺序 jump(优先级=${form.priority},值小排前)`,
    `iptables -t ${form.table} -A ${form.parent} -j ${name}`,
    '',
    `# 条目归属本组后规则落到 ${name}(继承钩子方向 ${form.parent})`
  ].join('\n')
})

const loadData = async () => {
  loading.value = true
  try {
    const data = await getCustomChains()
    chains.value = data.custom_chains || []
  } catch {
    ElMessage.error('加载策略组失败')
  } finally {
    loading.value = false
  }
}

const openAdd = () => {
  dialogTitle.value = '新增策略组'
  editingId.value = null
  Object.assign(form, { name: '', parent: 'MYFW-INPUT', table: 'filter', priority: 50, description: '', enabled: true })
  dialogVisible.value = true
}
const openEdit = (row) => {
  dialogTitle.value = '编辑策略组'
  editingId.value = row.id
  Object.assign(form, {
    name: row.name, parent: row.parent, table: row.table,
    priority: row.priority ?? 50,
    description: row.description || '', enabled: row.enabled
  })
  dialogVisible.value = true
}

const save = async () => {
  if (!formRef.value) return
  await formRef.value.validate()
  saving.value = true
  try {
    const payload = { name: form.name, parent: form.parent, table: form.table, priority: form.priority, description: form.description, enabled: form.enabled }
    if (editingId.value) {
      await updateCustomChain(editingId.value, payload)
      ElMessage.success('已更新')
    } else {
      await createCustomChain(payload)
      ElMessage.success('已创建')
    }
    dialogVisible.value = false
    loadData()
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '操作失败')
  } finally {
    saving.value = false
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(`确定删除策略组 MYFW-${row.name}?其下条目将不再生效`, '确认', { type: 'warning' })
    await deleteCustomChain(row.id)
    ElMessage.success('已删除')
    loadData()
  } catch {}
}

onMounted(loadData)
</script>

<style scoped>
.cc-page { width: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { margin: 0; font-size: 20px; font-weight: 600; color: var(--c-text-1); }
.tip { margin-bottom: 16px; }
.mono { font-family: 'JetBrains Mono', monospace; }
.form-hint { margin-left: 8px; font-size: 12px; color: var(--c-text-3); }
.cmd-preview { margin-top: 12px; border: 1px solid var(--c-border); border-radius: 6px; overflow: hidden; }
.cmd-preview-head { padding: 8px 12px; background: var(--c-surface-2); border-bottom: 1px solid var(--c-border); font-size: 12px; font-weight: 600; color: var(--c-text-1); }
.cmd-preview-code { margin: 0; padding: 12px; background: #1E293B; color: #E2E8F0; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
</style>
