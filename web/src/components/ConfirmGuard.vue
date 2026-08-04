<template>
  <div class="confirm-guard">
    <el-badge :value="count" :hidden="count === 0" :max="99" class="guard-badge">
      <el-button circle class="guard-btn" :class="{ urgent: hasUrgent }" @click="guard.open()">
        <el-icon><Clock /></el-icon>
      </el-button>
    </el-badge>

    <el-drawer v-model="guard.drawerOpen" title="保护期待确认" direction="rtl" size="460px">
      <div v-loading="loading" class="guard-list">
        <div v-if="!tasks.length && !loading" class="empty">暂无保护期内任务</div>
        <div v-for="t in tasks" :key="t.id" class="guard-card" :class="{ 'card-disable': t.change_type === 'disable', 'card-mixed': t.change_type === 'mixed' }" @click="openDetail(t)">
          <div class="card-top">
            <span class="card-node">🖥 {{ nodeIP(t.node_id) }}</span>
            <el-tag size="small" :type="changeTagType(t.change_type)" effect="dark">{{ changeLabel(t.change_type) }}</el-tag>
          </div>
          <div class="card-meta">操作者 {{ t.reviewer || '-' }} · {{ formatTime(t.created_at) }}</div>
          <div v-if="t.diff_after" class="card-diff"><pre class="diff-text">{{ diffSummary(t.diff_after) }}</pre></div>
          <el-progress
            :percentage="progress(t)"
            :color="progressColor(t)"
            :stroke-width="8"
            :show-text="false"
            :class="{ blink: isUrgent(t) }"
          />
          <div class="card-foot">
            <span class="countdown" :class="{ urgent: isUrgent(t) }">剩余 {{ remainText(t) }}</span>
            <div class="actions">
              <el-button size="small" type="success" @click.stop="handleConfirm(t)">确认</el-button>
              <el-button size="small" type="danger" @click.stop="handleRollback(t)">回滚</el-button>
            </div>
          </div>
        </div>
      </div>
    </el-drawer>

    <!-- 点击卡片弹出详情弹窗 -->
    <el-dialog v-model="detailVisible" title="任务详情" width="680px" :close-on-click-modal="false">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="策略">{{ detailTask.policy_name || '节点策略' }}</el-descriptions-item>
        <el-descriptions-item label="节点">{{ nodeIP(detailTask.node_id) }}</el-descriptions-item>
        <el-descriptions-item label="操作者">{{ detailTask.reviewer || '-' }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(detailTask.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="状态" :span="2">
          <el-tag :type="changeTagType(detailTask.change_type)" size="small">{{ changeLabel(detailTask.change_type) }}</el-tag>
          <span class="ml-2">剩余 {{ remainText(detailTask) }}</span>
        </el-descriptions-item>
      </el-descriptions>
      <div v-if="detailTask.diff_after" class="detail-diff">
        <h4>规则变更命令</h4>
        <pre class="diff-code">{{ detailTask.diff_after }}</pre>
      </div>
      <div v-else class="detail-diff">
        <h4>规则变更命令</h4>
        <p class="no-diff">暂无规则变更详情</p>
      </div>
      <template #footer>
        <el-button @click="goToNode(detailTask)">跳转节点策略</el-button>
        <el-button type="success" @click="handleConfirm(detailTask); detailVisible = false">确认生效</el-button>
        <el-button type="danger" @click="handleRollback(detailTask); detailVisible = false">回滚</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Clock } from '@element-plus/icons-vue'
import { getTasks, confirmTask, rollbackTask, getNodes } from '@/api'
import { useGuardStore } from '@/stores/guard'

const router = useRouter()
const guard = useGuardStore()
watch(() => guard.refreshTick, () => loadTasks())
const GUARD_SECONDS = 300
const URGENT_SECONDS = 60

const loading = ref(false)
const tasks = ref([])
const nodes = ref([])
const now = ref(Date.now())
const detailVisible = ref(false)
const detailTask = reactive({ id: '', node_id: '', policy_name: '', reviewer: '', created_at: '', diff_after: '', confirm_deadline: '', change_type: '' })

let pollTimer = null
let tickTimer = null

const count = computed(() => tasks.value.length)
const hasUrgent = computed(() => tasks.value.some((t) => remainSec(t) > 0 && remainSec(t) <= URGENT_SECONDS))

const nodeIP = (id) => {
  const n = nodes.value.find((x) => x.id === id)
  return n ? (n.ip || n.hostname || id.slice(0, 12)) : id.slice(0, 12)
}
// 变更类型标签:禁用任务红色显著标注,混合橙色,下发绿色
const changeLabel = (ct) => ({ disable: '禁用待确认', mixed: '混合变更', dispatch: '下发待确认' }[ct] || '保护期')
const changeTagType = (ct) => ({ disable: 'danger', mixed: 'warning', dispatch: 'success' }[ct] || 'warning')
const goToNode = (t) => {
  guard.close()
  router.push({ path: '/node-policies', query: { node: t.node_id } })
}
const openDetail = (t) => {
  Object.assign(detailTask, t)
  detailVisible.value = true
}
const formatTime = (t) => { if (!t) return '-'; try { return new Date(t).toLocaleString() } catch { return t } }
const diffSummary = (s) => {
  if (!s) return ''
  const lines = s.split('\n').filter((l) => l.trim())
  return lines.slice(0, 4).join('\n') + (lines.length > 4 ? `\n... 共 ${lines.length} 行` : '')
}

const deadlineMs = (t) => (t.confirm_deadline ? new Date(t.confirm_deadline).getTime() : 0)
const remainSec = (t) => {
  const d = deadlineMs(t)
  if (!d) return 0
  return Math.max(0, Math.floor((d - now.value) / 1000))
}
const isUrgent = (t) => remainSec(t) > 0 && remainSec(t) <= URGENT_SECONDS
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
  } catch { } finally { loading.value = false }
}
const loadNodes = async () => {
  try {
    const data = await getNodes()
    nodes.value = data.nodes || []
  } catch { }
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
  pollTimer = setInterval(loadTasks, 5000)
  tickTimer = setInterval(() => { now.value = Date.now() }, 1000)
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

.guard-card {
  border: 1px solid #e2e8f0; border-radius: 14px; padding: 14px; margin-bottom: 12px;
  background: #fff; cursor: pointer; transition: box-shadow .2s, transform .15s;
  box-shadow: 0 1px 3px rgba(0,0,0,.04);
}
.guard-card:hover { box-shadow: 0 6px 20px rgba(0,0,0,.08); transform: translateY(-1px); }
.guard-card.card-disable { border-color: #f56c6c; background: #fef0f0; }
.guard-card.card-disable:hover { box-shadow: 0 6px 20px rgba(245,108,108,.2); }
.guard-card.card-mixed { border-color: #e6a23c; background: #fdf6ec; }
.card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.card-node { font-weight: 600; font-size: 14px; color: #1e293b; font-family: 'Courier New', monospace; }
.card-meta { font-size: 12px; color: #94a3b8; margin-bottom: 8px; }
.card-diff { margin-bottom: 10px; }
.diff-text { margin: 0; padding: 8px; background: #0f172a; color: #e2e8f0; border-radius: 6px; font-size: 11px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; max-height: 100px; overflow: auto; }
.card-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
.countdown { font-size: 12px; color: #e6a23c; }
.countdown.urgent { color: #f56c6c; font-weight: 600; }
.actions { display: flex; gap: 8px; }

.detail-diff { margin-top: 16px; }
.detail-diff h4 { margin: 0 0 8px; color: #1e293b; font-size: 14px; }
.diff-code { margin: 0; padding: 12px; background: #0f172a; color: #e2e8f0; border-radius: 8px; font-size: 12px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; max-height: 420px; overflow: auto; }
.no-diff { color: #94a3b8; font-size: 13px; }
.ml-2 { margin-left: 8px; }
:deep(.el-progress--line) { margin-bottom: 0; }
:deep(.blink .el-progress-bar__outer) { animation: prog-blink 1s ease-in-out infinite; }
@keyframes prog-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
</style>