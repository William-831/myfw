/**
 * iptables 命令解析工具:从原始命令行提取操作类型/表/目标链/跳转目标,
 * 供专家模式实时高亮命令归属的父链与子链。仅做轻量正则解析,
 * 不校验语义(语义校验在 Agent 侧白名单完成)。
 */

// 六条 MYFW 父链(固定),含所属表--拓扑横向列与纵向分组的骨架
export const MYFW_PARENTS = [
  { name: 'MYFW-INPUT', table: 'filter', label: 'INPUT' },
  { name: 'MYFW-FORWARD', table: 'filter', label: 'FORWARD' },
  { name: 'MYFW-OUTPUT', table: 'filter', label: 'OUTPUT' },
  { name: 'MYFW-PREROUTING', table: 'nat', label: 'PREROUTING' },
  { name: 'MYFW-POSTROUTING', table: 'nat', label: 'POSTROUTING' },
  { name: 'MYFW-MANGLE', table: 'mangle', label: 'MANGLE' }
]

// 操作类型 -> 中文标签(实时归属提示与审计展示用)
export const OP_LABELS = {
  append: '追加',
  insert: '插入',
  delete: '删除',
  flush: '清空链',
  policy: '默认策略',
  newchain: '新建链',
  delchain: '删除链',
  unknown: '未识别'
}

/**
 * 判断链名是否属于 MYFW 命名空间(以 MYFW- 开头)
 * @param {string} chain
 * @returns {boolean}
 */
export function isMYFWChain(chain) {
  return /^MYFW-/.test(chain || '')
}

/**
 * 解析 iptables 命令,提取操作类型/表/目标链/跳转目标。
 * @param {string} cmd 原始命令
 * @returns {{op:string, table:string, chain:string, jump:string, raw:string}}
 *   op 取值: append/insert/delete/flush/policy/newchain/delchain/unknown
 *   table 默认 filter;chain 为 -A/-I/-D 等后的目标链;jump 为 -j 跳转目标
 */
export function parseIptablesCommand(cmd) {
  const trimmed = (cmd || '').trim()
  const result = { op: 'unknown', table: 'filter', chain: '', jump: '', raw: trimmed }
  if (!trimmed) return result

  // 表: -t nat(未指定则默认 filter)
  const tMatch = trimmed.match(/(?:^|\s)-t\s+(\S+)/)
  if (tMatch) result.table = tMatch[1]

  // 操作类型 + 目标链(-I 可带行号,如 -I MYFW-web 2)
  const opPatterns = [
    { re: /(?:^|\s)-A\s+(\S+)/, op: 'append' },
    { re: /(?:^|\s)-I\s+(\S+)(?:\s+\d+)?/, op: 'insert' },
    { re: /(?:^|\s)-D\s+(\S+)/, op: 'delete' },
    { re: /(?:^|\s)-F\s+(\S+)/, op: 'flush' },
    { re: /(?:^|\s)-P\s+(\S+)\s+(ACCEPT|DROP|RETURN|REJECT)/, op: 'policy' },
    { re: /(?:^|\s)-N\s+(\S+)/, op: 'newchain' },
    { re: /(?:^|\s)-X\s+(\S+)/, op: 'delchain' }
  ]
  for (const { re, op } of opPatterns) {
    const m = trimmed.match(re)
    if (m) {
      result.op = op
      result.chain = m[1]
      break
    }
  }

  // 跳转目标: -j MYFW-xxx
  const jMatch = trimmed.match(/(?:^|\s)-j\s+(\S+)/)
  if (jMatch) result.jump = jMatch[1]

  return result
}

/**
 * 根据目标链名定位所属 MYFW 父链。
 * 目标本身是父链时返回自身;是子链时查 customChains 取其 parent;
 * 非 MYFW 链返回空串(调用方据此提示"非 MYFW 命名空间")。
 * @param {string} chain 目标链名
 * @param {Array<{name:string,parent:string}>} customChains 自定义子链列表
 * @returns {string} 父链名(MYFW-INPUT 等)或空串
 */
export function locateParent(chain, customChains = []) {
  if (!isMYFWChain(chain)) return ''
  if (MYFW_PARENTS.some((p) => p.name === chain)) return chain
  const found = customChains.find((c) => c.name === chain)
  return found ? found.parent : ''
}
