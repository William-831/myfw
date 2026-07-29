/**
 * 时间格式化为本地可读字符串(24 小时制)
 * @param {string|number|Date} time
 * @returns {string}
 */
export function formatTime(time) {
  if (!time) return '-'
  try {
    return new Date(time).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return time
  }
}

/**
 * 相对时间(如"3 分钟前"),超过 7 天回退为日期
 * @param {string|number|Date} time
 * @returns {string}
 */
export function formatRelative(time) {
  if (!time) return '-'
  const ts = new Date(time).getTime()
  if (Number.isNaN(ts)) return typeof time === 'string' ? time : '-'
  const sec = Math.floor((Date.now() - ts) / 1000)
  if (sec < 60) return '刚刚'
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} 分钟前`
  const hour = Math.floor(min / 60)
  if (hour < 24) return `${hour} 小时前`
  const day = Math.floor(hour / 24)
  if (day < 7) return `${day} 天前`
  return new Date(time).toLocaleDateString('zh-CN')
}
