// 命令预览纯函数:根据表单/实例字段拼接底层 iptables 命令。
// 模板库(TemplateLibrary 编辑对话框)与节点策略实例列表/编辑对话框(NodePolicies)共用,
// 消除重复逻辑(DRY)。地址组经 ipset 匹配,ipset 名带 MYFW- 前缀(与 driver compileRule 一致)。
//
// MARK 白名单输出真实 3 条规则骨架(打标 + 白名单放行 + 兜底 DROP),参数未填处用占位符提示;
// 其余动作单条命令。
export function buildCommandPreview(f, chains = []) {
  // MARK 动作统一走白名单拦截骨架(3条规则)
  if (f.action === 'MARK') {
    const acl = f.direction === 'INPUT' ? 'MYFW-MARKACL-IN' : 'MYFW-MARKACL-FWD'
    const pp = f.port_range
      ? (f.protocol && f.protocol !== 'ANY' ? `-p ${f.protocol.toLowerCase()} --dport ${f.port_range}` : `--dport ${f.port_range}`)
      : '<请填端口>'
    const m = f.mark ? String(f.mark) : '<选标记值>'
    const src = f.source ? `-s ${f.source}`
      : (f.source_group ? `-m set --match-set MYFW-${f.source_group} src` : '<请填源地址/组>')
    return [
      { text: `iptables -t mangle -A MYFW-MARKMANGLE ${pp} -j MARK --set-mark ${m}`, type: 'mark' },
      { text: `iptables -t filter -A ${acl} ${src} -m mark --mark ${m} -j ACCEPT`, type: 'accept' },
      { text: `iptables -t filter -A ${acl} -m mark --mark ${m} -j DROP`, type: 'drop' },
    ]
  }
  const cc = chains.find((c) => c.id === f.group_id)
  const table = cc?.table || 'filter'
  const chain = cc ? `MYFW-${cc.name}` : 'MYFW-INPUT'
  const parts = ['iptables', '-t', table, '-A', chain]
  if (f.source) parts.push('-s', f.source)
  if (f.destination) parts.push('-d', f.destination)
  if (f.source_group) parts.push('-m', 'set', '--match-set', 'MYFW-' + f.source_group, 'src')
  if (f.destination_group) parts.push('-m', 'set', '--match-set', 'MYFW-' + f.destination_group, 'dst')
  if (f.protocol && f.protocol !== 'ANY') {
    parts.push('-p', f.protocol.toLowerCase())
    if (f.port_range && f.protocol !== 'ICMP') parts.push('--dport', f.port_range)
  }
  if (f.action === 'MARK') {
    parts.push('-j', 'MARK', '--set-mark', String(f.mark || 0))
  } else if (f.action === 'DNAT') {
    parts.push('-j', 'DNAT', ...(f.nat_to ? ['--to-destination', f.nat_to] : []))
  } else if (f.action === 'SNAT') {
    parts.push('-j', 'SNAT', ...(f.nat_to ? ['--to-source', f.nat_to] : []))
  } else if (f.action) {
    parts.push('-j', f.action)
  }
  return [{ text: parts.join(' '), type: 'default' }]
}
