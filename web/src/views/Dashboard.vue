<template>
  <div class="dashboard">
    <div class="stats-row">
      <el-card class="stat-card">
        <div class="stat-content">
          <div class="stat-icon node-icon">
            <el-icon><Connection /></el-icon>
          </div>
          <div class="stat-info">
            <p class="stat-value">{{ stats.node_count }}</p>
            <p class="stat-label">节点总数</p>
          </div>
        </div>
      </el-card>
      <el-card class="stat-card">
        <div class="stat-content">
          <div class="stat-icon online-icon">
            <el-icon><CircleCheck /></el-icon>
          </div>
          <div class="stat-info">
            <p class="stat-value">{{ stats.active_node_count }}</p>
            <p class="stat-label">在线节点</p>
          </div>
        </div>
      </el-card>
      <el-card class="stat-card">
        <div class="stat-content">
          <div class="stat-icon policy-icon">
            <el-icon><Lock /></el-icon>
          </div>
          <div class="stat-info">
            <p class="stat-value">{{ stats.policy_count }}</p>
            <p class="stat-label">策略总数</p>
          </div>
        </div>
      </el-card>
      <el-card class="stat-card">
        <div class="stat-content">
          <div class="stat-icon approve-icon">
            <el-icon><Clock /></el-icon>
          </div>
          <div class="stat-info">
            <p class="stat-value">{{ stats.pending_task_count }}</p>
            <p class="stat-label">待审批</p>
          </div>
        </div>
      </el-card>
    </div>

    <div class="charts-row">
      <el-card class="chart-card" style="flex: 1;">
        <template #header>
          <span>节点状态分布</span>
        </template>
        <div ref="nodeChartRef" class="chart"></div>
      </el-card>
      <el-card class="chart-card" style="flex: 1;">
        <template #header>
          <div class="audit-header">
            <span>最近审计记录</span>
            <el-button size="small" text @click="$router.push('/audit')">查看全部</el-button>
          </div>
        </template>
        <div v-loading="auditLoading" class="audit-list">
          <div v-if="recentAudits.length === 0" class="empty-tip">暂无审计记录</div>
          <div v-for="log in recentAudits" :key="log.id" class="audit-item">
            <span class="audit-action" :class="getActionClass(log.action)">{{ getActionLabel(log.action) }}</span>
            <span class="audit-detail">{{ log.detail }}</span>
            <span class="audit-time">{{ formatTime(log.created_at) }}</span>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, reactive } from 'vue'
import * as echarts from 'echarts'
import { Connection, CircleCheck, Lock, Clock } from '@element-plus/icons-vue'
import { getDashboardStats, getAuditLogs } from '@/api'

const auditLoading = ref(false)
const nodeChartRef = ref(null)
let nodeChart = null

const stats = reactive({
  node_count: 0,
  active_node_count: 0,
  pending_node_count: 0,
  abnormal_node_count: 0,
  policy_count: 0,
  active_policy_count: 0,
  pending_task_count: 0
})

const recentAudits = ref([])

// 节点状态饼图:在线/离线/待审核/异常
const updateNodeChart = () => {
  if (!nodeChart) return
  const offline = Math.max(0, stats.node_count - stats.active_node_count - stats.pending_node_count - stats.abnormal_node_count)
  nodeChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} 个 ({d}%)' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { color: '#6b7280', fontSize: 12 } },
    graphic: [
      { type: 'text', left: 'center', top: '38%', style: { text: `${stats.node_count}`, fontSize: 30, fontWeight: 'bold', fill: '#1f2937', textAlign: 'center' } },
      { type: 'text', left: 'center', top: '54%', style: { text: '节点总数', fontSize: 12, fill: '#9ca3af', textAlign: 'center' } }
    ],
    series: [{
      type: 'pie', radius: ['45%', '70%'], center: ['50%', '45%'],
      avoidLabelOverlap: false, cursor: 'pointer',
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      label: { show: false }, labelLine: { show: false },
      emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' }, scaleSize: 6 },
      data: [
        { value: stats.active_node_count, name: '在线', itemStyle: { color: '#67c23a' } },
        { value: offline, name: '离线', itemStyle: { color: '#909399' } },
        { value: stats.pending_node_count, name: '待审核', itemStyle: { color: '#e6a23c' } },
        { value: stats.abnormal_node_count, name: '异常', itemStyle: { color: '#f56c6c' } }
      ]
    }]
  })
}

const handleResize = () => nodeChart && nodeChart.resize()

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  nodeChart && nodeChart.dispose()
  nodeChart = null
})

const getActionLabel = (action) => {
  const map = {
    'node.register': '节点注册',
    'node.drift': '规则漂移',
    'node.heartbeat': '节点心跳',
    'node.archived': '节点归档',
    'policy.create': '策略创建',
    'policy.update': '策略更新',
    'policy.delete': '策略删除',
    'policy.apply': '策略应用',
    'task.submit': '任务提交',
    'task.approve': '任务审批',
    'task.reject': '任务拒绝',
    'task.confirm': '任务确认',
    'task.auto_rollback': '自动回滚',
    'task.applying_ok': '规则应用成功',
    'task.apply_failed': '规则应用失败',
    'auth.login': '用户登录'
  }
  return map[action] || action
}

const getActionClass = (action) => {
  if (action.includes('register') || action.includes('heartbeat') || action.includes('ok')) return 'success'
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback')) return 'warning'
  if (action.includes('apply') || action.includes('create') || action.includes('submit') || action.includes('approve')) return 'info'
  return 'default'
}

const formatTime = (time) => {
  if (!time) return '-'
  try {
    return new Date(time).toLocaleString()
  } catch {
    return time
  }
}

onMounted(async () => {
  if (nodeChartRef.value) {
    nodeChart = echarts.init(nodeChartRef.value)
    window.addEventListener('resize', handleResize)
  }
  try {
    const data = await getDashboardStats()
    Object.assign(stats, data)
  } catch {
    // 保持默认值
  }
  updateNodeChart()

  auditLoading.value = true
  try {
    const data = await getAuditLogs({ limit: 5, offset: 0 })
    recentAudits.value = data.data || []
  } catch {
    recentAudits.value = []
  } finally {
    auditLoading.value = false
  }
})
</script>

<style scoped>
.dashboard { width: 100%; }
.stats-row { display: flex; gap: 20px; margin-bottom: 20px; }
.stat-card { flex: 1; }
.stat-content { display: flex; align-items: center; }
.stat-icon { width: 64px; height: 64px; border-radius: 12px; display: flex; justify-content: center; align-items: center; margin-right: 16px; }
.stat-icon .el-icon { font-size: 28px; color: #fff; }
.node-icon { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.online-icon { background: linear-gradient(135deg, #67c23a 0%, #85ce61 100%); }
.policy-icon { background: linear-gradient(135deg, #409eff 0%, #66b1ff 100%); }
.approve-icon { background: linear-gradient(135deg, #e6a23c 0%, #ebb563 100%); }
.stat-info { flex: 1; }
.stat-value { font-size: 28px; font-weight: bold; color: #1f2937; margin: 0; }
.stat-label { font-size: 14px; color: #9ca3af; margin: 4px 0 0; }
.charts-row { display: flex; gap: 20px; }
.chart-card { height: 350px; }
.chart { width: 100%; height: 290px; }
.audit-header { display: flex; justify-content: space-between; align-items: center; }
.audit-list { height: 280px; overflow-y: auto; }
.empty-tip { text-align: center; color: #9ca3af; padding: 40px 0; }
.audit-item { display: flex; align-items: center; padding: 8px 0; border-bottom: 1px solid #f3f4f6; }
.audit-action { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; margin-right: 12px; white-space: nowrap; }
.audit-action.success { background-color: #f0f9ff; color: #67c23a; }
.audit-action.warning { background-color: #fef0f0; color: #f56c6c; }
.audit-action.info { background-color: #f0f5ff; color: #409eff; }
.audit-action.default { background-color: #f9fafb; color: #6b7280; }
.audit-detail { flex: 1; font-size: 13px; color: #374151; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-time { font-size: 12px; color: #9ca3af; margin-left: 12px; white-space: nowrap; }
</style>
