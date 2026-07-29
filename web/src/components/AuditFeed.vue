<template>
  <section class="panel">
    <header class="panel__head">
      <span>最近审计记录</span>
      <el-button size="small" text @click="$emit('view-all')">查看全部</el-button>
    </header>
    <div v-loading="loading" class="feed">
      <div v-if="!logs.length && !loading" class="feed__empty">暂无审计记录</div>
      <ul v-else class="timeline">
        <li v-for="log in logs" :key="log.id" class="tl-item">
          <div class="tl-item__axis">
            <span class="tl-item__dot" :class="getClass(log.action)"></span>
          </div>
          <div class="tl-item__main">
            <span class="tl-tag" :class="getClass(log.action)">{{ getLabel(log.action) }}</span>
            <span class="tl-item__detail">{{ log.detail }}</span>
          </div>
          <span class="tl-item__time" :title="formatTime(log.created_at)">{{ formatRelative(log.created_at) }}</span>
        </li>
      </ul>
      <div v-if="logs.length" class="feed__foot" @click="$emit('view-all')">
        <span v-if="total != null">共 {{ total }} 条记录</span>
        <span>查看全部 →</span>
      </div>
    </div>
  </section>
</template>

<script setup>
import { formatTime, formatRelative } from '@/composables/useFormat'

/**
 * 审计时间线:固定条数静态展示,状态色圆点 + 竖线 + 操作 pill + 相对时间
 */
defineProps({
  logs: { type: Array, default: () => [] },
  total: { type: Number, default: null },
  loading: { type: Boolean, default: false }
})

defineEmits(['view-all'])

// 操作类型中文映射
const LABELS = {
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

const getLabel = (action) => LABELS[action] || action

// 操作语义分类:成功 / 异常 / 操作 / 默认
const getClass = (action) => {
  if (action.includes('register') || action.includes('heartbeat') || action.includes('ok')) return 'success'
  if (action.includes('drift') || action.includes('failed') || action.includes('rollback')) return 'warning'
  if (action.includes('apply') || action.includes('create') || action.includes('submit') || action.includes('approve')) return 'info'
  return ''
}
</script>

<style scoped>
.panel {
  display: flex;
  flex-direction: column;
  min-height: 0;
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius);
  overflow: hidden;
}

.panel__head {
  flex: 0 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  font-size: 15px;
  font-weight: 600;
  color: var(--c-text-1);
  border-bottom: 1px solid var(--c-border-soft);
}

.feed {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
  padding: 6px 20px 12px;
}

.feed__empty {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--c-text-3);
  font-size: 13px;
}

.timeline {
  flex: 1;
  margin: 0;
  padding: 0;
  list-style: none;
}

.tl-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 8px 0;
}

.tl-item__axis {
  position: relative;
  flex: 0 0 16px;
  align-self: stretch;
  display: flex;
  justify-content: center;
  padding-top: 6px;
}

/* 时间线竖线:非末项,从圆点下方延伸至下一项 */
.tl-item:not(:last-child) .tl-item__axis::before {
  content: '';
  position: absolute;
  left: 50%;
  top: 20px;
  bottom: -8px;
  width: 2px;
  transform: translateX(-50%);
  background: var(--c-border-soft);
}

.tl-item__dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--c-info);
  z-index: 1;
}

.tl-item__dot.success { background: var(--c-success); }
.tl-item__dot.warning { background: var(--c-danger); }
.tl-item__dot.info { background: var(--c-primary); }

.tl-item__main {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  padding-top: 2px;
}

.tl-tag {
  flex: 0 0 auto;
  padding: 2px 8px;
  border-radius: var(--radius-xs);
  font-size: 12px;
  font-weight: 500;
  color: var(--c-text-3);
  background: var(--c-surface-2);
}

.tl-tag.success { color: var(--c-success); background: rgba(16, 185, 129, 0.1); }
.tl-tag.warning { color: var(--c-danger); background: rgba(244, 63, 94, 0.1); }
.tl-tag.info { color: var(--c-primary); background: var(--c-primary-soft); }

.tl-item__detail {
  flex: 1;
  min-width: 0;
  font-size: 13px;
  color: var(--c-text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tl-item__time {
  flex: 0 0 auto;
  padding-top: 3px;
  font-size: 12px;
  color: var(--c-text-3);
}

.feed__foot {
  flex: 0 0 auto;
  margin-top: auto;
  padding-top: 12px;
  border-top: 1px solid var(--c-border-soft);
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--c-text-3);
  cursor: pointer;
  transition: color var(--transition);
}

.feed__foot:hover {
  color: var(--c-primary);
}
</style>
