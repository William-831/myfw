<template>
  <div class="expert-page">
    <el-card>
      <template #header>
        <div class="header-row">
          <span>专家终端</span>
          <div class="header-actions">
            <el-select v-model="nodeId" placeholder="选择节点" style="width: 240px" @change="onNodeChange">
              <el-option v-for="n in nodes" :key="n.id" :label="nodeLabel(n)" :value="n.id" />
            </el-select>
            <el-button @click="clearHistory" :disabled="!history.length">清屏</el-button>
          </div>
        </div>
      </template>

      <!-- 风险提示 -->
      <el-alert type="warning" :closable="false" show-icon class="warn-banner">
        专家模式直接执行裸 iptables 命令，绕过 MYFW 命名空间、快照与保护期。误操作（如 -F / -P DROP）可能导致节点失联且平台无法回滚。每条命令均记入审计日志。
      </el-alert>

      <!-- 快捷命令 -->
      <div class="quick-bar">
        <el-button size="small" v-for="q in quickCommands" :key="q" @click="runQuick(q)">{{ q }}</el-button>
      </div>

      <!-- 命令输入 -->
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

      <!-- 命令历史记录 -->
      <div class="history-title">命令历史记录</div>
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
  </div>
</template>

<script setup>
import { ref, nextTick, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getNodes, execIptables } from '@/api'

const nodes = ref([])
const nodeId = ref('')
const command = ref('')
const history = ref([])
const running = ref(false)
const terminalRef = ref(null)
const inputRef = ref(null)

// 命令历史回溯栈（↑↓ 方向键）
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

const onNodeChange = () => inputRef.value?.focus()
const clearHistory = () => { history.value = [] }

const scrollToBottom = async () => {
  await nextTick()
  if (terminalRef.value) terminalRef.value.scrollTop = terminalRef.value.scrollHeight
}

// 危险命令判定：清空链 / 改默认策略为 DROP / 删除自定义链
const isDangerous = (cmd) => /\s(-F|--flush)\b|(-P)\s+(INPUT|OUTPUT|FORWARD)\s+DROP|\s(-X)\b/.test(cmd)

const execute = async () => {
  const cmd = command.value.trim()
  if (!cmd || !nodeId.value || running.value) return

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
  } catch (e) {
    entry.ok = false
    entry.output = e?.response?.data?.error || e?.message || '请求失败'
  } finally {
    running.value = false
    await scrollToBottom()
    inputRef.value?.focus()
  }
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

const loadNodes = async () => {
  try {
    const data = await getNodes()
    // 仅列出 ACTIVE 节点（离线节点无法执行）
    nodes.value = (data.nodes || []).filter(n => n.status === 'ACTIVE')
    if (nodes.value.length && !nodeId.value) {
      nodeId.value = nodes.value[0].id
      await nextTick()
      inputRef.value?.focus()
    }
  } catch {
    ElMessage.error('加载节点列表失败')
  }
}

onMounted(loadNodes)
</script>

<style scoped>
.header-row { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 12px; align-items: center; }
.warn-banner { margin-bottom: 12px; }
.quick-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }

.history-title { font-size: 13px; font-weight: 600; color: #94a3b8; margin: 12px 0 6px; }

.terminal {
  background: #0f172a;
  border: 1px solid var(--c-border);
  border-radius: 8px;
  padding: 12px 16px;
  height: 440px;
  overflow-y: auto;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 13px;
  color: #cbd5e1;
}
.empty-hint { color: #64748b; padding: 16px 0; line-height: 1.6; }
.entry { margin-bottom: 10px; }
.cmd-line { color: #94a3b8; display: flex; align-items: center; }
.entry-time { color: #64748b; font-size: 11px; margin-right: 8px; font-family: 'JetBrains Mono', 'Consolas', monospace; }
.prompt { color: #38bdf8; margin-right: 6px; }
.cmd { color: #e2e8f0; }
.output {
  margin: 4px 0 0 16px;
  white-space: pre-wrap;
  word-break: break-all;
  color: #cbd5e1;
  font-family: inherit;
}
.entry.ok .output { color: #86efac; }
.entry.err .output { color: #fca5a5; }
.entry.running { color: #fbbf24; }

.input-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  background: #0f172a;
  border: 1px solid var(--c-border);
  border-radius: 8px;
  padding: 8px 12px;
}
.input-row .prompt { color: #38bdf8; }
.cmd-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: #e2e8f0;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 13px;
}
.cmd-input::placeholder { color: #475569; }
.cmd-input:disabled { cursor: not-allowed; }
</style>
