<template>
  <div class="confirm-guard">
    <!-- 顶部常驻角标:数字为保护期内任务数,有紧急任务时图标闪烁 -->
    <el-badge :value="count" :hidden="count === 0" :max="99" class="guard-badge">
      <el-button circle class="guard-btn" :class="{ urgent: hasUrgent }" @click="guard.open()">
        <el-icon><Clock /></el-icon>
      </el-button>
    </el-badge>

    <el-drawer v-model="guard.drawerOpen" title="保护期待确认" direction="rtl" size="440px">
      <div v-loading="loading" class="guard-list">
        <div v-if="!tasks.length && !loading" class="empty">暂无保护期内任务</div>
        <div v-for="t in tasks" :key="t.id" class="guard-item">
          <div class="item-head">
            <span class="policy-name">{{ t.policy_name || '(单条规则)' }}</span>
            <span class="node-ip">{{ nodeIP(t.node_id) }}</span>
          </div>
          <el-progress
            :percentage="progress(t)"
            :color="progressColor(t)"
            :stroke-width="10"
            :show-text="false"
            :class="{ blink: isUrgent(t) }"
          />
          <div class="item-foot">
            <span class="countdown" :class="{ urgent: isUrgent(t) }">剩余 {{ remainText(t) }}</span>
            <div class="actions">
              <el-button size="small" type="success" @click="handleConfirm(t)">确认</el-button>
              <el-button size="small" type="danger" @click="handleRollback(t)">回滚</el-button>
            </div>
          </div>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Clock } from '@element-plus/icons-vue'
import { getTasks, confirmTask, rollbackTask, getNodes } from '@/api'
import { useGuardStore } from '@/stores/guard'

const GUARD_SECONDS = 300 // 保护期总时长,与后端 DefaultConfirmDeadline 一致
const URGENT_SECONDS = 60 // 最后 60s 视为紧急,红+闪

const guard = useGuardStore()
const loading = ref(false)
const tasks = ref([])
const nodes = ref([])
const now = ref(Date.now())

let pollTimer = null
let tickTimer = null

const count = computed(() => tasks.value.length)
const hasUrgent = computed(() => tasks.value.some((t) => remainSec(t) > 0 && remainSec(t) <= URGENT_SECONDS))

const nodeIP = (id) => {
  const n = nodes.value.find((x) => x.id === id)
  return n ? (n.ip || n.hostname || id.slice(0, 12)) : id.slice(0, 12)
}

const deadlineMs = (t) => (t.confirm_deadline ? new Date(t.confirm_deadline).getTime() : 0)
const remainSec = (t) => {
  const d = deadlineMs(t)
  if (!d) return 0
  return Math.max(0, Math.floor((d - now.value) / 1000))
}
const isUrgent = (t) => {
  const r = remainSec(t)
  return r > 0 && r <= URGENT_SECONDS
}
const progress = (t) => Math.min(100, Math.round((remainSec(t) / GUARD_SECONDS) * 100))
const progressColor = (t) => (isUrgent(t) ? '#f56c6c' : '#e6a23c')
const remainText = (t) => {
  const r = remainSec(t)
  if (r <= 0) return '已超时'
  const m = Math.floor(r / 60)
  const s = r % 60
  return `${m}分${s}秒`
}

const loadTasks = async () => {
  loading.value = true
  try {
    const data = await getTasks({ status: 'confirm_wait' })
    tasks.value = data.tasks || []
  } catch {
    // 静默失败,不打断用户当前操作
  } finally {
    loading.value = false
  }
}
const loadNodes = async () => {
  try {
    const data = await getNodes()
    nodes.value = data.nodes || []
  } catch {
    // 节点列表加载失败不影响倒计时展示
  }
}

const handleConfirm = async (t) => {
  try {
    await ElMessageBox.confirm(
      `确认「${t.policy_name || '单条规则'}」生效?将保留当前规则。`,
      '确认生效',
      { type: 'success', confirmButtonText: '确认', cancelButtonText: '取消' }
    )
    await confirmTask(t.id)
    ElMessage.success('已确认生效')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '确认失败')
  }
}

const handleRollback = async (t) => {
  try {
    await ElMessageBox.confirm(
      `回滚「${t.policy_name || '单条规则'}」?节点将恢复到变更前状态。`,
      '确认回滚',
      { type: 'warning', confirmButtonText: '回滚', cancelButtonText: '取消' }
    )
    await rollbackTask(t.id)
    ElMessage.success('已回滚')
    loadTasks()
  } catch (err) {
    if (err !== 'cancel') ElMessage.error(err?.response?.data?.error || '回滚失败')
  }
}

onMounted(() => {
  loadNodes()
  loadTasks()
  pollTimer = setInterval(loadTasks, 10000) // 10s 轮询刷新任务列表
  tickTimer = setInterval(() => { now.value = Date.now() }, 1000) // 1s 更新倒计时
})
onUnmounted(() => {
  clearInterval(pollTimer)
  clearInterval(tickTimer)
})
</script>

<style scoped>
.confirm-guard { display: inline-flex; align-items: center; }
.guard-btn { background: var(--el-fill-color-light, #f5f7fa); border-color: transparent; }
.guard-btn.urgent { animation: guard-blink 1s ease-in-out infinite; }
@keyframes guard-blink {
  0%, 100% { background: #f56c6c; color: #fff; }
  50% { background: #fef0f0; color: #f56c6c; }
}
.guard-list { padding: 0 4px; }
.empty { text-align: center; color: #909399; padding: 40px 0; font-size: 13px; }
.guard-item {
  border: 1px solid var(--el-border-color-lighter, #ebeef5);
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 12px;
}
.item-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.policy-name { font-weight: 600; color: #1e293b; }
.node-ip { font-family: 'Courier New', monospace; font-size: 12px; color: #64748b; }
.item-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
.countdown { font-size: 12px; color: #e6a23c; }
.countdown.urgent { color: #f56c6c; font-weight: 600; }
.actions { display: flex; gap: 8px; }
:deep(.el-progress--line) { margin-bottom: 0; }
:deep(.blink .el-progress-bar__outer) { animation: prog-blink 1s ease-in-out infinite; }
@keyframes prog-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
</style>
