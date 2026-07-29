<template>
  <div class="ag-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">地址组管理</h2>
        <el-tag size="small" type="info">{{ groups.length }} 个组</el-tag>
      </div>
      <el-button type="primary" @click="openAdd">
        <el-icon><Plus /></el-icon>新增地址组
      </el-button>
    </div>

    <el-alert type="info" :closable="false" class="tip">
      地址组是白/黑名单 IP 段集合,编译期绑定到节点 ipset / nft set。策略通过「源地址组 / 目的地址组」引用其名称,即可用一条规则批量匹配多 CIDR。
    </el-alert>

    <el-table :data="groups" v-loading="loading" stripe>
      <el-table-column label="名称" width="180">
        <template #default="{ row }"><span class="mono">{{ row.name }}</span></template>
      </el-table-column>
      <el-table-column label="类型" width="110">
        <template #default="{ row }">
          <el-tag :type="kindType(row.kind)" size="small">{{ kindLabel(row.kind) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="成员数" width="80" align="center">
        <template #default="{ row }">{{ (row.members || []).length }}</template>
      </el-table-column>
      <el-table-column label="成员 (CIDR)" min-width="320">
        <template #default="{ row }">
          <div class="members">
            <el-tag v-for="m in (row.members || [])" :key="m" size="small" class="cidr">{{ m }}</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="描述" prop="description" min-width="150" show-overflow-tooltip />
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button size="small" text type="warning" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" text type="danger" @click="handleDelete(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="560px" :close-on-click-modal="false">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="90px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="如 whitelist / blacklist / ops-team" />
        </el-form-item>
        <el-form-item label="类型" prop="kind">
          <el-select v-model="form.kind" style="width: 100%">
            <el-option label="白名单 (whitelist)" value="whitelist" />
            <el-option label="黑名单 (blacklist)" value="blacklist" />
            <el-option label="自定义 (custom)" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="成员 CIDR" prop="members">
          <el-select
            v-model="form.members"
            multiple filterable allow-create
            default-first-option
            :reserve-keyword="false"
            placeholder="输入 CIDR 后回车,如 10.0.0.0/8"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="2" />
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
import { getAddressGroups, createAddressGroup, updateAddressGroup, deleteAddressGroup } from '@/api'

const loading = ref(false)
const saving = ref(false)
const groups = ref([])
const dialogVisible = ref(false)
const dialogTitle = ref('新增地址组')
const formRef = ref(null)
const editingId = ref(null)

const form = reactive({ name: '', kind: 'whitelist', members: [], description: '' })
const rules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  kind: [{ required: true, message: '请选择类型', trigger: 'change' }]
}

const kindLabel = (k) => ({ whitelist: '白名单', blacklist: '黑名单', custom: '自定义' }[k] || k)
const kindType = (k) => ({ whitelist: 'success', blacklist: 'danger', custom: 'info' }[k] || 'info')

// 命令预览:复刻后端 iptables driver 的 ipset 编译逻辑,让用户直观看到将生成的底层命令
const previewCmd = computed(() => {
  const set = `MYFW-${form.name || '<name>'}`
  const members = (form.members || []).length ? form.members : ['<cidr>...']
  return [
    '# 创建集合 (hash:net)',
    `ipset create ${set} hash:net -exist`,
    '',
    '# 灌入成员',
    ...members.map(m => `ipset add ${set} ${m} -exist`),
    '',
    '# 策略引用 (在 MYFW-INPUT 内)',
    `iptables -t filter -A MYFW-INPUT -m set --match-set ${set} src -j ${form.kind === 'blacklist' ? 'DROP' : 'ACCEPT'}`
  ].join('\n')
})

const loadData = async () => {
  loading.value = true
  try {
    const data = await getAddressGroups()
    groups.value = data.address_groups || []
  } catch {
    ElMessage.error('加载地址组失败')
  } finally {
    loading.value = false
  }
}

const openAdd = () => {
  dialogTitle.value = '新增地址组'
  editingId.value = null
  Object.assign(form, { name: '', kind: 'whitelist', members: [], description: '' })
  dialogVisible.value = true
}
const openEdit = (row) => {
  dialogTitle.value = '编辑地址组'
  editingId.value = row.id
  Object.assign(form, {
    name: row.name, kind: row.kind,
    members: [...(row.members || [])], description: row.description || ''
  })
  dialogVisible.value = true
}

const save = async () => {
  if (!formRef.value) return
  await formRef.value.validate()
  saving.value = true
  try {
    const payload = { name: form.name, kind: form.kind, members: form.members, description: form.description }
    if (editingId.value) {
      await updateAddressGroup(editingId.value, payload)
      ElMessage.success('已更新')
    } else {
      await createAddressGroup(payload)
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
    await ElMessageBox.confirm(`确定删除地址组 ${row.name}?`, '确认', { type: 'warning' })
    await deleteAddressGroup(row.id)
    ElMessage.success('已删除')
    loadData()
  } catch {}
}

onMounted(loadData)
</script>

<style scoped>
.ag-page { width: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { margin: 0; font-size: 20px; font-weight: 600; color: var(--c-text-1); }
.tip { margin-bottom: 16px; }
.mono { font-family: 'JetBrains Mono', monospace; }
.members { display: flex; flex-wrap: wrap; gap: 4px; }
.cidr { font-family: 'JetBrains Mono', monospace; }
.cmd-preview { margin-top: 12px; border: 1px solid var(--c-border); border-radius: 6px; overflow: hidden; }
.cmd-preview-head { padding: 8px 12px; background: var(--c-surface-2); border-bottom: 1px solid var(--c-border); font-size: 12px; font-weight: 600; color: var(--c-text-1); }
.cmd-preview-code { margin: 0; padding: 12px; background: #1E293B; color: #E2E8F0; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
</style>
