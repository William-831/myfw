<template>
  <div class="dashboard">
    <!-- 顶部 KPI:极简数字卡,一屏固定 -->
    <div class="stat-row">
      <StatCard :icon="Connection" :value="stats.node_count" label="节点总数" accent="var(--c-primary)" :sub="nodeSub" />
      <StatCard :icon="CircleCheck" :value="stats.active_node_count" label="在线节点" accent="var(--c-success)" :sub="onlineSub" />
      <StatCard :icon="Lock" :value="stats.policy_count" label="策略总数" accent="var(--c-info)" :sub="policySub" />
      <StatCard :icon="Clock" :value="stats.pending_task_count" label="待审批" accent="var(--c-warning)" :sub="pendingSub" />
      <StatCard :icon="Warning" :value="configDrift.total" label="配置漂移" accent="var(--c-danger)" :sub="driftSub" />
    </div>

    <!-- 主区:左节点状态环形图 + 右审计时间线,等高填满剩余空间 -->
    <div class="main-row">
      <StatusPanel
        :total="stats.node_count"
        :active="stats.active_node_count"
        :pending="stats.pending_node_count"
        :abnormal="stats.abnormal_node_count"
      />
      <AuditFeed
        :logs="recentAudits"
        :total="auditTotal"
        :loading="auditLoading"
        @view-all="$router.push('/audit')"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { Connection, CircleCheck, Lock, Clock, Warning } from '@element-plus/icons-vue'
import { getDashboardStats, getAuditLogs, getConfigDrift } from '@/api'
import { usePolling } from '@/composables/usePolling'
import StatCard from '@/components/StatCard.vue'
import StatusPanel from '@/components/StatusPanel.vue'
import AuditFeed from '@/components/AuditFeed.vue'

const auditLoading = ref(false)
const recentAudits = ref([])
const auditTotal = ref(null)

const stats = reactive({
  node_count: 0,
  active_node_count: 0,
  pending_node_count: 0,
  abnormal_node_count: 0,
  policy_count: 0,
  active_policy_count: 0,
  pending_task_count: 0
})

// 配置漂移(模板已更新但实例未跟)统计,与运行时规则漂移区分
const configDrift = reactive({ total: 0, nodes: [] })
const driftSub = computed(() => configDrift.total ? `涉及 ${configDrift.nodes.length} 个节点 · 可一键同步` : '模板与实例一致')

// 占比工具:node_count 为 0 时返回 0
const pct = (n) => (stats.node_count ? Math.round((n / stats.node_count) * 100) : 0)

// KPI 副信息(互补,避免与主数值重复)
const nodeSub = computed(() => stats.node_count ? `在线 ${stats.active_node_count} · 待审 ${stats.pending_node_count}` : '暂无节点')
const onlineSub = computed(() => stats.node_count ? `在线率 ${pct(stats.active_node_count)}%` : '')
const policySub = computed(() => `生效 ${stats.active_policy_count}`)
const pendingSub = computed(() => stats.pending_task_count ? '待处理' : '暂无待办')

// 仪表盘 KPI/配置漂移/最近审计统一加载。silent=true 轮询刷新不置 auditLoading,
// 避免每 10s 时间线 loading 闪烁。
const loadDashboard = async ({ silent = false } = {}) => {
  try {
    Object.assign(stats, await getDashboardStats())
  } catch {
    // 保持默认值
  }

  try {
    Object.assign(configDrift, await getConfigDrift())
  } catch { /* 配置漂移加载失败不阻塞 */ }

  if (!silent) auditLoading.value = true
  try {
    const data = await getAuditLogs({ limit: 6, offset: 0 })
    recentAudits.value = data.data || []
    auditTotal.value = data.total ?? data.count ?? null
  } catch {
    recentAudits.value = []
  } finally {
    if (!silent) auditLoading.value = false
  }
}
// 仪表盘状态实时性强(节点数/在线/待审批/漂移/最近审计),10s 轮询自动刷新,免手动刷新页面
usePolling(() => loadDashboard({ silent: true }), 10000)
onMounted(loadDashboard)
</script>

<style scoped>
/* 一屏钉死:height:100% 吃满父级 content box,告别 calc 魔法数字 */
.dashboard {
  height: 100%;
  display: flex;
  flex-direction: column;
  gap: var(--gap);
  overflow: hidden;
}

.stat-row {
  flex: 0 0 auto;
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: var(--gap);
}

.main-row {
  flex: 1 1 auto;
  min-height: 0;
  display: grid;
  grid-template-columns: 5fr 7fr;
  gap: var(--gap);
}
</style>
