<template>
  <div class="dashboard">
    <div class="stats-row">
      <el-card class="stat-card">
        <div class="stat-content">
          <div class="stat-icon node-icon">
            <el-icon><Network /></el-icon>
          </div>
          <div class="stat-info">
            <p class="stat-value">{{ stats.totalNodes }}</p>
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
            <p class="stat-value">{{ stats.onlineNodes }}</p>
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
            <p class="stat-value">{{ stats.totalPolicies }}</p>
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
            <p class="stat-value">{{ stats.pendingApprovals }}</p>
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
          <span>最近审计记录</span>
        </template>
        <div class="audit-list">
          <div v-for="log in recentAudits" :key="log.id" class="audit-item">
            <span class="audit-action" :class="getActionClass(log.action)">{{ log.action }}</span>
            <span class="audit-detail">{{ log.detail }}</span>
            <span class="audit-time">{{ formatTime(log.createdAt) }}</span>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive } from 'vue'
import * as echarts from 'echarts'
import { Network, CircleCheck, Lock, Clock } from '@element-plus/icons-vue'

const nodeChartRef = ref(null)

const stats = reactive({
  totalNodes: 5,
  onlineNodes: 4,
  totalPolicies: 23,
  pendingApprovals: 2
})

const recentAudits = [
  { id: 1, action: 'node.register', detail: '节点 node-01 注册成功', createdAt: '2024-01-15 10:30:00' },
  { id: 2, action: 'policy.apply', detail: '策略 policy-001 已应用到节点 node-01', createdAt: '2024-01-15 10:25:00' },
  { id: 3, action: 'node.drift', detail: '检测到节点 node-02 规则漂移', createdAt: '2024-01-15 10:20:00' },
  { id: 4, action: 'policy.create', detail: '创建策略 allow-ssh', createdAt: '2024-01-15 10:15:00' },
  { id: 5, action: 'node.heartbeat', detail: '节点 node-03 心跳正常', createdAt: '2024-01-15 10:10:00' }
]

const getActionClass = (action) => {
  if (action.includes('register') || action.includes('heartbeat')) return 'success'
  if (action.includes('drift')) return 'warning'
  if (action.includes('apply') || action.includes('create')) return 'info'
  return 'default'
}

const formatTime = (time) => {
  return time
}

onMounted(() => {
  if (nodeChartRef.value) {
    const chart = echarts.init(nodeChartRef.value)
    chart.setOption({
      tooltip: {
        trigger: 'item'
      },
      legend: {
        bottom: 0
      },
      series: [
        {
          name: '节点状态',
          type: 'pie',
          radius: ['40%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#fff',
            borderWidth: 2
          },
          label: {
            show: false
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 18,
              fontWeight: 'bold'
            }
          },
          data: [
            { value: 4, name: '在线', itemStyle: { color: '#67c23a' } },
            { value: 1, name: '离线', itemStyle: { color: '#f56c6c' } }
          ]
        }
      ]
    })
  }
})
</script>

<style scoped>
.dashboard {
  width: 100%;
}

.stats-row {
  display: flex;
  gap: 20px;
  margin-bottom: 20px;
}

.stat-card {
  flex: 1;
}

.stat-content {
  display: flex;
  align-items: center;
}

.stat-icon {
  width: 64px;
  height: 64px;
  border-radius: 12px;
  display: flex;
  justify-content: center;
  align-items: center;
  margin-right: 16px;
}

.stat-icon .el-icon {
  font-size: 28px;
  color: #fff;
}

.node-icon {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.online-icon {
  background: linear-gradient(135deg, #67c23a 0%, #85ce61 100%);
}

.policy-icon {
  background: linear-gradient(135deg, #409eff 0%, #66b1ff 100%);
}

.approve-icon {
  background: linear-gradient(135deg, #e6a23c 0%, #ebb563 100%);
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #1f2937;
  margin: 0;
}

.stat-label {
  font-size: 14px;
  color: #9ca3af;
  margin: 4px 0 0;
}

.charts-row {
  display: flex;
  gap: 20px;
}

.chart-card {
  height: 350px;
}

.chart {
  width: 100%;
  height: 280px;
}

.audit-list {
  height: 280px;
  overflow-y: auto;
}

.audit-item {
  display: flex;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #f3f4f6;
}

.audit-action {
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  margin-right: 12px;
}

.audit-action.success {
  background-color: #f0f9ff;
  color: #67c23a;
}

.audit-action.warning {
  background-color: #fef0f0;
  color: #f56c6c;
}

.audit-action.info {
  background-color: #f0f5ff;
  color: #409eff;
}

.audit-action.default {
  background-color: #f9fafb;
  color: #6b7280;
}

.audit-detail {
  flex: 1;
  font-size: 13px;
  color: #374151;
}

.audit-time {
  font-size: 12px;
  color: #9ca3af;
}
</style>