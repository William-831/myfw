<template>
  <div class="dashboard">
    <!-- 顶部 KPI:极简数字卡,一屏固定 -->
    <div class="stat-row">
      <StatCard :icon="Connection" :value="stats.node_count" label="节点总数" accent="var(--c-primary)" :sub="nodeSub" />
      <StatCard :icon="CircleCheck" :value="stats.active_node_count" label="在线节点" accent="var(--c-success)" :sub="onlineSub" />
      <StatCard :icon="Lock" :value="stats.policy_count" label="策略总数" accent="var(--c-info)" :sub="policySub" />
      <StatCard :icon="Clock" :value="stats.pending_task_count" label="待审批" accent="var(--c-warning)" :sub="pendingSub" />
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
import { Connection, CircleCheck, Lock, Clock } from '@element-plus/icons-vue'
import { getDashboardStats, getAuditLogs } from '@/api'
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

// 占比工具:node_count 为 0 时返回 0
const pct = (n) => (stats.node_count ? Math.round((n / stats.node_count) * 100) : 0)

// KPI 副信息(互补,避免与主数值重复)
const nodeSub = computed(() => stats.node_count ? `在线 ${stats.active_node_count} · 待审 ${stats.pending_node_count}` : '暂无节点')
const onlineSub = computed(() => stats.node_count ? `在线率 ${pct(stats.active_node_count)}%` : '')
const policySub = computed(() => `生效 ${stats.active_policy_count}`)
const pendingSub = computed(() => stats.pending_task_count ? '待处理' : '暂无待办')

onMounted(async () => {
  try {
    Object.assign(stats, await getDashboardStats())
  } catch {
    // 保持默认值
  }

  auditLoading.value = true
  try {
    const data = await getAuditLogs({ limit: 6, offset: 0 })
    recentAudits.value = data.data || []
    auditTotal.value = data.total ?? data.count ?? null
  } catch {
    recentAudits.value = []
  } finally {
    auditLoading.value = false
  }
})
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
  grid-template-columns: repeat(4, 1fr);
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
