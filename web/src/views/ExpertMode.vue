<template>
  <div class="expert-page">
    <!-- 专家终端(置顶优先):工具栏 + 命令输入 + 执行反馈 -->
    <el-card class="terminal-card">
      <template #header>
        <div class="header-row">
          <span class="title">专家终端</span>
          <div class="header-actions">
            <el-select v-model="nodeId" placeholder="选择节点" style="width: 240px" @change="onNodeChange">
              <el-option v-for="n in nodes" :key="n.id" :label="nodeLabel(n)" :value="n.id" />
            </el-select>
            <el-button @click="clearHistory" :disabled="!history.length">清屏</el-button>
          </div>
        </div>
      </template>

      <el-alert type="warning" :closable="false" show-icon class="warn-banner">
        专家模式直接执行裸 iptables 命令，绕过 MYFW 命名空间、快照与保护期。误操作（如 -F / -P DROP）可能导致节点失联且平台无法回滚。每条命令均记入审计日志。
      </el-alert>

      <!-- 命令输入 + 实时归属提示 -->
      <div class="input-row">
        <span class="prompt">$</span>
        <input
          ref="inputRef"
          v-model="command"
          class="cmd-input"
          :placeholder="nodeId ? '输入 iptables 命令后回车（↑↓ 回溯历史）' : '请先选择节点'"
          :disabled="!nodeId || running"
          @keydown.enter="execute"
          @keydown.up.prevent="recallPrev"
          @keydown.down.prevent="recallNext"
        />
        <el-button type="primary" @click="execute" :loading="running" :disabled="!nodeId">执行</el-button>
      </div>
      <div v-if="command.trim()" class="parse-hint">
        <el-tag size="small" :type="opTagType">{{ opLabel }}</el-tag>
        <span v-if="parsed.chain" class="hint-seg">目标链: <code>{{ parsed.chain }}</code></span>
        <span v-if="parsed.jump" class="hint-seg">跳转: <code>{{ parsed.jump }}</code></span>
        <span v-if="locateInfo" class="hint-seg ok">归属: {{ locateInfo }}</span>
        <span v-else-if="parsed.chain && !isMYFWChain(parsed.chain)" class="hint-seg warn">非 MYFW 命名空间（平台不纳管）</span>
        <span v-else-if="parsed.chain && isMYFWChain(parsed.chain) && !highlightParent" class="hint-seg warn">MYFW 子链未在平台注册</span>
      </div>
      <div class="quick-bar">
        <el-button size="small" v-for="q in quickCommands" :key="q" @click="runQuick(q)">{{ q }}</el-button>
      </div>

      <!-- 执行反馈终端 -->
      <div class="terminal" ref="terminalRef">
        <div v-if="!history.length" class="empty-hint">
          选择节点后输入 iptables 命令（回车执行），仅允许 iptables 族命令：iptables / ip6tables / iptables-save / iptables-restore / nft。
        </div>
        <div v-for="(h, i) in history" :key="i" class="entry" :class="{ ok: h.ok, err: !h.ok }">
          <div class="cmd-line">
            <span class="entry-time">{{ h.time }}</span>
            <span class="prompt">$</span>
            <span class="cmd">{{ h.command }}</span>
          </div>
          <pre class="output">{{ h.output }}</pre>
        </div>
        <div v-if="running" class="entry running"><span class="prompt">$</span> 执行中...</div>
      </div>
    </el-card>

    <!-- 链规则浏览器:父链 -> 子链 -> 规则(两级折叠) -->
    <el-card class="browser-card">
      <template #header>
        <div class="card-header">
          <span>规则拓扑</span>
          <span class="card-sub">父链调度 -> 子链执行 -> 规则明细，点击展开</span>
          <div class="card-actions">
            <el-button size="small" @click="toggleCollapseAll">{{ allCollapsed ? '展开全部' : '一键折叠' }}</el-button>
            <el-button size="small" @click="loadRules" :loading="loadingRules">刷新规则</el-button>
          </div>
        </div>
      </template>
      <el-empty v-if="!parentsWithChains.length" description="暂无已部署子链" :image-size="60" />
      <div v-else class="browser">
        <div
          v-for="p in parentsWithChains"
          :key="p.name"
          class="parent-node"
          :class="{ highlight: highlightParent === p.name }"
        >
          <div class="parent-header" @click="toggleParent(p.name)">
            <span class="arrow">{{ openedParents.includes(p.name) ? '▼' : '▶' }}</span>
            <span class="parent-label">{{ p.label }}</span>
            <span class="parent-name">{{ p.name }}</span>
            <span class="parent-meta">{{ subchainsOf(p.name).length }} 子链 · {{ ruleCountOfParent(p.name) }} 规则</span>
          </div>
          <div v-show="openedParents.includes(p.name)" class="subchain-list">
            <div
              v-for="sc in subchainsOf(p.name)"
              :key="sc.name"
              class="subchain-node"
              :class="{ highlight: highlightChain === sc.name, flash: flashChain === sc.name }"
            >
              <div class="subchain-header" @click="toggleChain(sc.name)">
                <span class="arrow">{{ openedChains.includes(sc.name) ? '▼' : '▶' }}</span>
                <span class="chain-name">{{ sc.name }}</span>
                <span class="chain-meta">{{ rulesOfChain(sc.name).length }} 条</span>
              </div>
              <div v-show="openedChains.includes(sc.name)" class="rule-list">
                <div v-for="r in rulesOfChain(sc.name)" :key="r.id" class="rule-line">
                  <span class="rule-priority">{{ r.priority }}</span>
                  <code class="rule-text">{{ r.rule_line }}</code>
                </div>
                <div v-if="!rulesOfChain(sc.name).length" class="rule-empty">该子链暂无规则</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getNodes, getNodeIptablesRules, execIptables, getCustomChains } from '@/api'
import {
  MYFW_PARENTS,
  OP_LABELS,
  isMYFWChain,
  parseIptablesCommand,
  locateParent
} from '@/composables/useIptablesParse'

const nodes = ref([])
const nodeId = ref('')
const command = ref('')
const history = ref([])
const running = ref(false)
const loadingRules = ref(false)
const terminalRef = ref(null)
const inputRef = ref(null)

// 拓扑骨架(平台注册的自定义子链)与节点实际规则
const customChains = ref([])
const rules = ref([])

// 两级折叠状态:父链 / 子链;lastOpened 供一键折叠恢复
const openedParents = ref([])
const openedChains = ref([])
const lastOpenedParents = ref([])
const lastOpenedChains = ref([])
const flashChain = ref('')

// 命令历史回溯栈(↑↓ 方向键)
const cmdStack = ref([])
const stackIdx = ref(0)

// 常用命令快捷按钮
const quickCommands = [
  'iptables -L -n',
  'iptables -S',
  'iptables-save',
  'iptables -t nat -L -n',
  'iptables -t mangle -L -n'
]

const nodeLabel = (n) => `${n.ip || n.hostname || n.id.slice(0, 12)}`

// 实时解析当前输入命令
const parsed = computed(() => parseIptablesCommand(command.value))
const opLabel = computed(() => OP_LABELS[parsed.value.op] || '未识别')
const opTagType = computed(() => {
  const danger = { flush: 'danger', delchain: 'danger', policy: 'warning' }
  return danger[parsed.value.op] || 'info'
})

// 高亮:目标链 + 其所属父链(浏览器中定位归属)
const highlightChain = computed(() => (isMYFWChain(parsed.value.chain) ? parsed.value.chain : ''))
const highlightParent = computed(() => locateParent(parsed.value.chain, customChains.value))

// 归属提示文本
const locateInfo = computed(() => {
  if (!highlightChain.value || !highlightParent.value) return ''
  const parentLabel = MYFW_PARENTS.find((p) => p.name === highlightParent.value)?.label || highlightParent.value
  return highlightChain.value === highlightParent.value
    ? `父链 ${parentLabel}`
    : `${parentLabel} / ${highlightChain.value.replace('MYFW-', '')}`
})

// 一键折叠:父链与子链全收起即为全折叠
const allCollapsed = computed(() => !openedParents.value.length && !openedChains.value.length)

// 某父链下的子链(按全局优先级排序)
const subchainsOf = (parent) =>
  customChains.value
    .filter((c) => c.parent === parent)
    .sort((a, b) => (a.priority || 0) - (b.priority || 0))

// 某子链内的实际规则(按优先级排序)
const rulesOfChain = (chain) =>
  rules.value
    .filter((r) => r.chain === chain)
    .sort((a, b) => (a.priority || 0) - (b.priority || 0))

// 某父链下所有子链的规则总数
const ruleCountOfParent = (parent) =>
  subchainsOf(parent).reduce((sum, sc) => sum + rulesOfChain(sc.name).length, 0)

// 浏览器只展示有子链的父链(保持界面清爽)
const parentsWithChains = computed(() => MYFW_PARENTS.filter((p) => subchainsOf(p.name).length > 0))

const onNodeChange = () => {
  loadRules()
  inputRef.value?.focus()
}

const toggleParent = (name) => {
  const i = openedParents.value.indexOf(name)
  if (i >= 0) openedParents.value.splice(i, 1)
  else openedParents.value.push(name)
}

const toggleChain = (name) => {
  const i = openedChains.value.indexOf(name)
  if (i >= 0) openedChains.value.splice(i, 1)
  else openedChains.value.push(name)
}

const toggleCollapseAll = () => {
  if (openedParents.value.length || openedChains.value.length) {
    // 记住当前展开层级后全部收起,仅留终端(宏观视角)
    lastOpenedParents.value = [...openedParents.value]
    lastOpenedChains.value = [...openedChains.value]
    openedParents.value = []
    openedChains.value = []
  } else {
    // 恢复上次展开层级;无记忆则展开全部
    openedParents.value = lastOpenedParents.value.length
      ? [...lastOpenedParents.value]
      : parentsWithChains.value.map((p) => p.name)
    openedChains.value = lastOpenedChains.value.length
      ? [...lastOpenedChains.value]
      : customChains.value.map((c) => c.name)
  }
}

const clearHistory = () => {
  history.value = []
}

const scrollToBottom = async () => {
  await nextTick()
  if (terminalRef.value) terminalRef.value.scrollTop = terminalRef.value.scrollHeight
}

// 危险命令判定:清空链 / 改默认策略为 DROP / 删除自定义链
const isDangerous = (cmd) => /\s(-F|--flush)\b|(-P)\s+(INPUT|OUTPUT|FORWARD)\s+DROP|\s(-X)\b/.test(cmd)

const execute = async () => {
  const cmd = command.value.trim()
  if (!cmd || !nodeId.value || running.value) return

  // 执行前快照目标链,用于执行后自动展开与高亮
  const targetChain = parsed.value.chain
  const targetIsMYFW = isMYFWChain(targetChain)

  // 危险命令二次确认
  if (isDangerous(cmd)) {
    try {
      await ElMessageBox.confirm(
        `命令「${cmd}」可能清空规则或修改默认策略，导致节点失联且平台无法回滚。确认执行？`,
        '危险操作确认',
        { type: 'error', confirmButtonText: '确认执行', cancelButtonText: '取消' }
      )
    } catch {
      return
    }
  }

  // 入历史回溯栈
  if (cmdStack.value[cmdStack.value.length - 1] !== cmd) cmdStack.value.push(cmd)
  stackIdx.value = cmdStack.value.length

  command.value = ''
  running.value = true
  const entry = { command: cmd, ok: false, output: '', time: new Date().toLocaleTimeString() }
  history.value.push(entry)
  await scrollToBottom()

  try {
    const res = await execIptables(nodeId.value, cmd)
    entry.ok = !!res.ok
    entry.output = res.output || (res.ok ? '(无输出)' : '(执行失败)')
    // 执行成功后刷新规则,展开并高亮受影响子链(连同其父链)
    await loadRules()
    if (targetIsMYFW) {
      const parent = locateParent(targetChain, customChains.value)
      if (parent && !openedParents.value.includes(parent)) openedParents.value.push(parent)
      if (!openedChains.value.includes(targetChain)) openedChains.value.push(targetChain)
      flashTarget(targetChain)
    }
  } catch (e) {
    entry.ok = false
    entry.output = e?.response?.data?.error || e?.message || '请求失败'
  } finally {
    running.value = false
    await scrollToBottom()
    inputRef.value?.focus()
  }
}

// 高亮目标子链 1.5s 后恢复(执行后定位反馈)
const flashTarget = (chain) => {
  flashChain.value = chain
  setTimeout(() => {
    if (flashChain.value === chain) flashChain.value = ''
  }, 1500)
}

const runQuick = (q) => {
  command.value = q
  execute()
}

// ↑ 回溯上一条
const recallPrev = () => {
  if (!cmdStack.value.length) return
  if (stackIdx.value > 0) stackIdx.value--
  command.value = cmdStack.value[stackIdx.value] || ''
}

// ↓ 回溯下一条
const recallNext = () => {
  if (stackIdx.value < cmdStack.value.length - 1) {
    stackIdx.value++
    command.value = cmdStack.value[stackIdx.value] || ''
  } else {
    stackIdx.value = cmdStack.value.length
    command.value = ''
  }
}

// 拉取节点最新规则(准实时:后端先向 Agent 拉取再返回)
const loadRules = async () => {
  if (!nodeId.value) return
  loadingRules.value = true
  try {
    const data = await getNodeIptablesRules(nodeId.value)
    rules.value = data.rules || []
  } catch {
    ElMessage.error('加载节点规则失败')
  } finally {
    loadingRules.value = false
  }
}

// 拉取平台注册的自定义子链(拓扑骨架)
const loadCustomChains = async () => {
  try {
    const data = await getCustomChains()
    customChains.value = data.custom_chains || []
  } catch {
    ElMessage.error('加载策略组失败')
  }
}

const loadNodes = async () => {
  try {
    const data = await getNodes()
    // 仅列出 ACTIVE 节点(离线节点无法执行)
    nodes.value = (data.nodes || []).filter((n) => n.status === 'ACTIVE')
    if (nodes.value.length && !nodeId.value) {
      nodeId.value = nodes.value[0].id
      await nextTick()
      inputRef.value?.focus()
      loadRules()
    }
  } catch {
    ElMessage.error('加载节点列表失败')
  }
}

onMounted(() => {
  loadCustomChains()
  loadNodes()
})
</script>

<style scoped>
.expert-page {
  display: flex;
  flex-direction: column;
  gap: var(--gap);
}

.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}
.title {
  font-weight: 600;
  color: var(--c-text-1);
}
.warn-banner {
  margin-bottom: 12px;
}

/* 命令输入 */
.input-row {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
}
.prompt {
  color: #38bdf8;
  font-family: var(--font-mono);
}
.cmd-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--c-text-1);
  font-family: var(--font-mono);
  font-size: 13px;
}
.cmd-input::placeholder {
  color: var(--c-text-2);
}
.cmd-input:disabled {
  cursor: not-allowed;
}
.parse-hint {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 10px;
  font-size: 12px;
  color: var(--c-text-2);
  flex-wrap: wrap;
}
.hint-seg code {
  background: var(--c-surface-2);
  padding: 1px 6px;
  border-radius: var(--radius-xs);
  font-family: var(--font-mono);
  color: var(--c-text-1);
}
.hint-seg.ok {
  color: var(--c-success);
}
.hint-seg.warn {
  color: var(--c-warning);
}
.quick-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

/* 执行反馈终端 */
.terminal {
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  margin-top: 12px;
  height: 280px;
  overflow-y: auto;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--c-text-2);
}
.empty-hint {
  color: #64748b;
  padding: 16px 0;
  line-height: 1.6;
}
.entry {
  margin-bottom: 10px;
}
.cmd-line {
  color: var(--c-text-3);
  display: flex;
  align-items: center;
}
.entry-time {
  color: #64748b;
  font-size: 11px;
  margin-right: 8px;
}
.cmd {
  color: var(--c-text-1);
}
.output {
  margin: 4px 0 0 16px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--c-text-2);
  font-family: inherit;
}
.entry.ok .output {
  color: #86efac;
}
.entry.err .output {
  color: #fca5a5;
}
.entry.running {
  color: #fbbf24;
}

/* 链规则浏览器 */
.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
}
.card-actions {
  margin-left: auto;
  display: flex;
  gap: 8px;
}
.card-sub {
  font-size: 12px;
  color: var(--c-text-3);
  font-weight: 400;
}
.browser {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.parent-node {
  border: 1px solid var(--c-border);
  border-radius: var(--radius-sm);
  background: var(--c-surface-2);
  transition: border-color var(--transition), box-shadow var(--transition);
}
.parent-node.highlight {
  border-color: var(--c-primary);
  box-shadow: 0 0 0 2px var(--c-primary-soft);
}
.parent-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  cursor: pointer;
  user-select: none;
  border-radius: var(--radius-sm);
}
.parent-header:hover {
  background: var(--c-surface);
}
.arrow {
  color: var(--c-text-3);
  font-size: 11px;
  width: 12px;
}
.parent-label {
  font-weight: 600;
  color: var(--c-text-1);
  font-size: 14px;
}
.parent-name {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--c-text-3);
}
.parent-meta {
  margin-left: auto;
  font-size: 12px;
  color: var(--c-text-3);
}
.subchain-list {
  padding: 0 14px 8px 28px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.subchain-node {
  border: 1px solid var(--c-border);
  border-radius: var(--radius-xs);
  background: var(--c-surface);
  transition: all var(--transition);
}
.subchain-node.highlight {
  border-color: var(--c-primary);
  background: var(--c-primary-soft);
}
.subchain-node.flash {
  animation: flash 1.5s ease;
}
@keyframes flash {
  0%,
  100% {
    box-shadow: 0 0 0 0 transparent;
  }
  30% {
    box-shadow: 0 0 0 3px var(--c-primary-soft);
  }
}
.subchain-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  cursor: pointer;
  user-select: none;
}
.subchain-header:hover {
  background: var(--c-surface-2);
}
.chain-name {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--c-text-1);
}
.chain-meta {
  margin-left: auto;
  font-size: 12px;
  color: var(--c-text-3);
}
.rule-list {
  padding: 2px 10px 8px 26px;
}
.rule-line {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 3px 0;
  font-size: 12px;
}
.rule-priority {
  color: var(--c-text-3);
  font-family: var(--font-mono);
  min-width: 24px;
  text-align: right;
}
.rule-text {
  font-family: var(--font-mono);
  color: var(--c-text-2);
  word-break: break-all;
}
.rule-empty {
  color: var(--c-text-3);
  font-size: 12px;
  padding: 4px 0;
}
</style>
