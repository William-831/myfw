<template>
  <div class="settings-page">
    <el-card>
      <template #header>保留设置</template>
      <el-form :model="form" label-width="160px" v-loading="loading">
        <el-form-item label="审计日志保留(天)">
          <el-input-number v-model="form.audit_retention_days" :min="1" :max="365" />
          <span class="hint">超过保留期的审计日志定时清理(默认 30 天)</span>
        </el-form-item>
        <el-form-item label="审批任务保留(天)">
          <el-input-number v-model="form.task_retention_days" :min="1" :max="365" />
          <span class="hint">已完成的审批任务(确认/回滚/失败)超期自动清理(默认 7 天)</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="save" :loading="saving">保存设置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="cleanup-card">
      <template #header>手动清理异常数据</template>
      <el-alert type="warning" :closable="false" class="tip">
        清理:卡死任务(applying/dispatching 超 1 小时未推进)+ 超时待审批(创建超 24 小时)+ 已完成超保留期任务 + 超保留期审计日志。定时任务每天自动执行一次。
      </el-alert>
      <el-button type="danger" @click="doCleanup" :loading="cleaning">立即清理</el-button>
      <div v-if="cleanupResult" class="result">
        <h4>清理结果</h4>
        <ul>
          <li>卡死任务: <b>{{ cleanupResult.stuck_tasks }}</b></li>
          <li>超时待审批: <b>{{ cleanupResult.timeout_pending_tasks }}</b></li>
          <li>过期已完成任务: <b>{{ cleanupResult.expired_tasks }}</b></li>
          <li>过期审计日志: <b>{{ cleanupResult.expired_audit_logs }}</b></li>
        </ul>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getRetention, updateRetention, cleanupNow } from '@/api'

const loading = ref(false)
const saving = ref(false)
const cleaning = ref(false)
const form = reactive({ audit_retention_days: 30, task_retention_days: 7 })
const cleanupResult = ref(null)

const load = async () => {
  loading.value = true
  try {
    const d = await getRetention()
    form.audit_retention_days = d.audit_retention_days || 30
    form.task_retention_days = d.task_retention_days || 7
  } catch { ElMessage.error('加载设置失败') } finally { loading.value = false }
}
const save = async () => {
  saving.value = true
  try {
    await updateRetention(form)
    ElMessage.success('已保存')
  } catch (e) { ElMessage.error(e?.response?.data?.error || '保存失败') } finally { saving.value = false }
}
const doCleanup = async () => {
  cleaning.value = true
  try {
    const d = await cleanupNow()
    cleanupResult.value = d
    ElMessage.success('清理完成')
  } catch (e) { ElMessage.error(e?.response?.data?.error || '清理失败') } finally { cleaning.value = false }
}
onMounted(load)
</script>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 16px; }
.hint { margin-left: 12px; color: #94a3b8; font-size: 12px; }
.cleanup-card .tip { margin-bottom: 12px; }
.result { margin-top: 12px; padding: 12px; background: #f8fafc; border-radius: 6px; }
.result h4 { margin: 0 0 8px; color: #1e293b; }
.result ul { margin: 0; padding-left: 20px; color: #475569; line-height: 1.8; }
</style>
