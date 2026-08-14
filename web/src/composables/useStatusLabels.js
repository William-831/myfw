import { computed } from 'vue'

// 任务状态标签映射(集中):Approve 审批页 + ConfirmGuard 保护期面板共用。
// 简化语义:对外只显 待审批/待确认/已通过/已拒绝/已回滚/已接管,中间态统一"处理中"。
const LABELS = {
  pending_approval: '待审批',
  confirm_wait: '待确认',
  confirmed: '已通过',
  failed: '已拒绝',
  rolled_back: '已回滚',
  superseded: '已接管',
  approved: '处理中', dispatching: '处理中', applying: '处理中',
}
const TYPES = {
  pending_approval: 'warning',
  confirmed: 'success',
  failed: 'danger',
  rolled_back: 'danger',
  superseded: 'info',
  approved: 'info', dispatching: 'info', applying: 'info', confirm_wait: 'info',
}

// 任务状态 -> 中文标签 / Element tag 类型(未收录回退原始状态 / info)
export function useStatusLabels(status) {
  return {
    label: computed(() => LABELS[status] || status),
    type: computed(() => TYPES[status] || 'info'),
  }
}

export { LABELS, TYPES }
