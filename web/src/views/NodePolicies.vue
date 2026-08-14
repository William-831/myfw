<template>
  <div class="np-page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">节点策略</h2>
        <el-tag size="small" type="info">以节点为中心管理策略实例</el-tag>
      </div>
      <div class="header-right">
        <el-switch v-model="expertMode" active-text="专家终端" inactive-text="实例配置" />
      </div>
    </div>
    <ExpertMode v-if="expertMode" />
    <!-- 保护期是节点级:顶部仅保留整体待确认提示(点击跳转面板确认);具体到实例的
         接管/待确认定位由各实例条目的"⏳ 新状态待确认"标签承载,不再单独出接管 banner -->
    <el-alert
      v-if="guardTask"
      type="warning"
      :closable="false"
      class="guard-banner"
      @click="guard.open()"
    >
      <div class="guard-banner-main">⏰ 该节点有保护期待确认任务 — 操作者 {{ guardTask.reviewer || '-' }}，{{ guardTask.policy_name || '节点全量变更' }}，点击前往确认<template v-if="recentSuperseded">；旧任务 {{ recentSuperseded.id }} 已被新动作接管,保护期已重置</template></div>
      <pre v-if="guardTask.diff_after" class="guard-banner-diff">{{ guardTask.diff_after }}</pre>
    </el-alert>
    <el-row :gutter="14" class="np-body">
      <!-- 左:节点列表 -->
      <el-col :span="6">
        <el-card class="node-card" v-loading="nodesLoading">
          <template #header><span>节点</span></template>
          <div v-if="!nodes.length && !nodesLoading" class="empty-mini">暂无节点</div>
          <div v-for="n in nodes" :key="n.id" class="node-item" :class="{ active: n.id === selectedNodeId }" @click="selectNode(n)">
            <el-badge :value="n.drift_count" :hidden="!n.drift_count" class="node-badge" type="warning">
              <span class="node-ip">{{ n.ip || n.hostname || n.id.slice(0, 12) }}</span>
            </el-badge>
            <el-tag :type="n.status === 'ACTIVE' ? 'success' : 'info'" size="small">{{ n.status === 'ACTIVE' ? '在线' : '离线' }}</el-tag>
          </div>
        </el-card>
      </el-col>
      <!-- 右:实例列表 -->
      <el-col :span="18">
        <el-card class="inst-card" v-loading="instLoading">
          <template #header>
            <div class="inst-head">
              <span>{{ currentNodeLabel }} 的策略实例 ({{ instances.length }})</span>
              <div class="inst-actions">
                <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '点击创建一条新的策略实例(手动填写五元组与动作)'" placement="top">
                  <el-button size="small" type="primary" @click="openCreate" :disabled="!selectedNodeId || nodeBusy"><el-icon><Plus /></el-icon>新建策略</el-button>
                </el-tooltip>
                <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '从模板库实例化一条策略,自动填充模板参数,可按节点特化源 IP 等字段'" placement="top">
                  <el-button size="small" @click="openInstantiate" :disabled="!selectedNodeId || nodeBusy"><el-icon><Plus /></el-icon>从模板实例化</el-button>
                </el-tooltip>
                <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '将该节点全部已启用实例编译下发到节点,并删除不在期望态中的多余规则(全量对齐);保护期内新动作将接管旧任务并重置保护期'" placement="top">
                  <el-button size="small" type="success" @click="handleDispatch" :disabled="!selectedNodeId || !instances.length || nodeBusy" :loading="dispatching">下发节点(全量对齐)</el-button>
                </el-tooltip>
                <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '将漂移实例一键同步到模板最新参数;模板空值字段保留实例当前特化值'" placement="top">
                  <el-button size="small" type="warning" @click="handleSyncAll" :disabled="!selectedNodeId || !driftInstanceCount || nodeBusy" :loading="syncingAll">同步全部漂移({{ driftInstanceCount }})</el-button>
                </el-tooltip>
                <el-tooltip content="仅显示死规则:启用+已采集命中统计+packets=0+创建超3天,建议移除" placement="top">
                  <el-checkbox v-model="onlyDead" size="small" class="dead-filter">仅看死规则</el-checkbox>
                </el-tooltip>
              </div>
            </div>
          </template>
          <div v-if="!selectedNodeId" class="empty-mini">请选择左侧节点</div>
          <div v-else-if="!instances.length" class="empty-mini">该节点暂无策略实例,点"从模板实例化"添加</div>
          <div v-else class="inst-list">
            <div v-for="inst in sortedInstances" :key="inst.id" class="inst-item" :class="{ disabled: !inst.enabled, drift: inst.drift, 'not-applied': inst.enabled && !inst.applied }">
              <div class="inst-top">
                <span class="inst-name">{{ inst.name }}</span>
                <el-tooltip content="该实例所属的策略模板" placement="top">
                  <el-tag size="small" type="info">模板: {{ inst.template_name || '-' }}</el-tag>
                </el-tooltip>
                <el-tooltip v-if="inst.drift" :content="driftFieldsText(inst)" placement="top">
                  <el-tag type="warning" size="small" effect="dark">⚠ 模板已更新({{ inst.deviated_fields?.length || 0 }}字段)</el-tag>
                </el-tooltip>
                <el-tooltip v-if="inst.pending_delete" content="移除已进入保护期,等待确认;确认后规则彻底移除,回滚则恢复实例" placement="top">
                  <el-tag size="small" type="warning" effect="dark">待确认移除</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="nodeInGuard && pendingConfirmIntents.get(inst.id)" :content="pendingConfirmIntents.get(inst.id) === 'remove' ? '该实例移除已进入保护期,待确认;确认后移除,回滚恢复实例' : '该实例新状态已下发,处于保护期待确认;确认后生效,回滚恢复原状'" placement="top">
                  <el-tag size="small" type="warning" effect="dark">{{ pendingConfirmIntents.get(inst.id) === 'remove' ? '⏳ 移除待确认' : '⏳ 下发待确认' }}</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="nodeInGuard && !inst.enabled" content="节点保护期内:新动作已下发,未确认前处于保护期(节点规则未变),确认后新状态才生效" placement="top">
                  <el-tag size="small" type="warning" effect="dark">⏳ 保护期接管中</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="inst.chain_unavailable" content="所属规则链已被禁用或删除,该实例暂无法下发" placement="top">
                  <el-tag size="small" type="danger" effect="dark">⚠ 链不可用</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="inst.enabled && !inst.applied" content="实例已启用但规则尚未下发到节点(或下发中)" placement="top">
                  <el-tag size="small" type="warning" effect="dark">未下发</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="inst.enabled && inst.applied" content="实例已成功下发,节点规则已生效" placement="top">
                  <el-tag size="small" type="success" effect="plain">已下发</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="!inst.enabled && inst.applied" content="实例已禁用但节点规则仍存在,等待移除确认" placement="top">
                  <el-tag size="small" type="danger" effect="dark">待移除</el-tag>
                </el-tooltip>
                <el-tooltip v-if="ruleHitsMap[inst.id]?.dead" content="死规则:创建3天没命中(启用+已采集+packets=0),建议移除" placement="top">
                  <el-tag size="small" type="info" effect="dark">死规则</el-tag>
                </el-tooltip>
                <el-tooltip :content="nodeInGuard && pendingConfirmIntents.get(inst.id) ? '节点保护期内,新状态待确认,确认后生效' : (nodeInGuard && !inst.enabled ? '节点保护期内,新状态待确认,确认后生效' : '实例启用状态;禁用后规则将从节点移除(走保护期)')" placement="top">
                  <el-tag :type="inst.enabled ? 'success' : 'info'" size="small">{{ nodeInGuard && pendingConfirmIntents.get(inst.id) ? '待确认' : (nodeInGuard && !inst.enabled ? '保护期中' : (inst.enabled ? '启用' : '禁用')) }}</el-tag>
                </el-tooltip>
              </div>
              <div class="inst-rule">
                <span class="field"><span class="lbl">协议</span>{{ inst.protocol || 'ANY' }}</span>
                <span class="field"><span class="lbl">端口</span>{{ inst.port_range || '任意' }}</span>
                <span class="field"><span class="lbl">源</span>{{ inst.source || '任意' }}</span>
                <span class="field"><span class="lbl">目的</span>{{ inst.destination || '任意' }}</span>
                <span v-if="inst.source_group" class="field"><span class="lbl">源组</span>{{ inst.source_group }}</span>
                <span v-if="inst.destination_group" class="field"><span class="lbl">目的组</span>{{ inst.destination_group }}</span>
                <span class="action" :class="inst.action ? inst.action.toLowerCase() : ''">{{ getActionLabel(inst.action) }}</span>
              </div>
              <div class="inst-foot">
                <div class="foot-left">
                  <span class="prio">优先级 #{{ inst.priority }}</span>
                  <el-tooltip content="该实例规则最近采集的命中包数(pkts)/流量(bytes);0 且超 3 天判为死规则" placement="top">
                    <span class="hits">命中 {{ formatHits(ruleHitsMap[inst.id]) }}</span>
                  </el-tooltip>
                  <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '启用/禁用实例;禁用后规则将从节点移除并进入保护期;保护期内新动作将接管旧任务并重置保护期'" placement="top">
                    <el-switch :model-value="inst.enabled" size="small" :disabled="nodeBusy" @change="(v) => toggleEnabled(inst, v)" />
                  </el-tooltip>
                </div>
                <div class="actions">
                  <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '流量预演:按该实例五元组仿真命中路径、iptables 命令与最终判定'" placement="top">
                    <el-button size="small" text type="primary" :disabled="nodeBusy" @click="openInstSimulate(inst)"><el-icon><VideoPlay /></el-icon>预演</el-button>
                  </el-tooltip>
                  <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '编辑该实例的策略参数(源/目的/端口/动作等),不影响模板'" placement="top">
                    <el-button size="small" text type="warning" :disabled="nodeBusy" @click="openEditInst(inst)">编辑参数</el-button>
                  </el-tooltip>
                  <el-tooltip v-if="inst.drift" :content="nodeBusy ? '节点有任务执行中,请稍候' : '同步为模板最新参数;模板空值字段保留实例当前特化值'" placement="top">
                    <el-button size="small" text type="primary" :disabled="nodeBusy" @click="handleSync(inst)">同步模板</el-button>
                  </el-tooltip>
                  <el-tooltip :content="nodeBusy ? '节点有任务执行中,请稍候' : '移除该实例;已下发时走保护期(确认后删除/可回滚),未下发直接删除;保护期内新动作将接管旧任务'" placement="top">
                    <el-button size="small" text type="danger" :disabled="inst.pending_delete || nodeBusy" @click="handleDeleteInst(inst)">移除</el-button>
                  </el-tooltip>
                </div>
              </div>
              <div class="inst-cmd">
                <code v-for="(line, i) in buildCommandPreview(inst, customChains)" :key="i" :class="'cmd-' + line.type">{{ line.text }}</code>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 单条策略流量预演(计划二):预期目标 vs 实际模拟通道 + 自然语言结论 + iptables 命令预览 -->
    <el-drawer v-model="simVisible" :title="'流量预演 - ' + (simInst?.name || '')" size="72%" direction="rtl" destroy-on-close>
      <div class="sim-layout">
        <div class="sim-form-bar">
          <div class="sim-fields">
            <el-select v-model="simForm.direction" style="width: 118px">
              <el-option label="入站 INPUT" value="INPUT" />
              <el-option label="转发 FORWARD" value="FORWARD" />
              <el-option label="出站 OUTPUT" value="OUTPUT" />
            </el-select>
            <el-input v-model="simForm.source_ip" placeholder="源 IP,空=任意" clearable style="width: 136px" />
            <el-input v-model="simForm.dest_ip" placeholder="目的 IP,空=任意" clearable style="width: 136px" />
            <el-select v-model="simForm.protocol" style="width: 100px">
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="ICMP" value="icmp" />
              <el-option label="任意" value="" />
            </el-select>
            <el-input-number v-model="simForm.dst_port" :min="0" :max="65535" controls-position="right" style="width: 112px" placeholder="目的端口" />
            <el-button type="primary" @click="handleSimulate" :loading="simLoading">
              <el-icon style="margin-right: 4px"><VideoPlay /></el-icon>预演
            </el-button>
          </div>
          <div class="sim-form-hint">按该节点当前期望规则集做 filter 表无状态匹配;方向已按策略所在链推断,可改;NAT/mangle 仅提示不模拟。</div>
        </div>

        <!-- 判定横幅:最终判定 + 自然语言结论 -->
        <div v-if="simResult" class="sim-verdict-banner" :class="'verdict-' + simResult.verdict.toLowerCase()">
          <div class="verdict-icon">{{ verdictMeta.icon }}</div>
          <div class="verdict-main">
            <div class="verdict-title">
              <span class="verdict-tag">{{ simResult.verdict }}</span>
              <span class="verdict-label">{{ verdictMeta.label }}</span>
            </div>
            <div class="verdict-conclusion">{{ simResult.conclusion || simResult.note || '未生成结论' }}</div>
          </div>
        </div>

        <el-row :gutter="16" class="sim-body">
          <!-- 左:预期目标 -->
          <el-col :span="8">
            <div class="sim-panel sim-expected">
              <div class="sim-panel-title">你的预期目标</div>
              <div v-if="simInst" class="expected-detail">
                <div class="exp-row"><span class="exp-lbl">实例</span>{{ simInst.name }}</div>
                <div class="exp-row"><span class="exp-lbl">协议</span>{{ (simInst.protocol || 'ANY').toUpperCase() }}</div>
                <div class="exp-row"><span class="exp-lbl">端口</span>{{ simInst.port_range || '任意' }}</div>
                <div class="exp-row"><span class="exp-lbl">源</span>{{ simInst.source_group || simInst.source || '任意' }}</div>
                <div class="exp-row"><span class="exp-lbl">目的</span>{{ simInst.destination || '任意' }}</div>
                <div class="exp-row"><span class="exp-lbl">动作</span><span class="exp-action" :class="(simInst.action || '').toLowerCase()">{{ getActionLabel(simInst.action) }}</span></div>
                <div class="expected-verdict">预期: {{ expectedText(simInst) }}</div>
              </div>
            </div>
          </el-col>

          <!-- 右:实际模拟步骤流(垂直时间轴 + 命中高亮 + 命令代码块) -->
          <el-col :span="16">
            <div class="sim-panel sim-actual">
              <div class="sim-panel-title">实际模拟过程和结果</div>
              <div v-if="simResult" class="sim-steps">
                <div class="sim-step-entry">入口 · {{ simForm.direction }}</div>
                <template v-for="(s, i) in simResult.steps" :key="i">
                  <div class="sim-step" :class="{ hit: s.matched, term: isTerminalStep(i) }">
                    <div class="step-rail"><span class="step-dot" /></div>
                    <div class="step-body">
                      <div class="step-head">
                        <span class="step-chain">{{ s.chain }}</span>
                        <span class="step-action" :class="s.action.toLowerCase()">{{ s.action }}</span>
                        <span class="step-rule">{{ s.rule_id }}</span>
                        <el-tag v-if="s.matched" size="small" :type="nodeTagType(s)" class="step-tag">{{ s.action === 'MARK' ? '打标' : '命中' }}</el-tag>
                        <span v-if="isTerminalStep(i)" class="step-term-badge">终止</span>
                      </div>
                      <code class="step-cmd">{{ s.command }}</code>
                      <div v-if="s.note" class="node-note">{{ s.note }}</div>
                    </div>
                  </div>
                </template>
                <div class="sim-step-entry sim-step-end" :class="'end-' + simResult.verdict.toLowerCase()">终点 · {{ simResult.verdict }}</div>
                <div v-if="!simResult.steps.length" class="sim-empty">无规则参与匹配</div>
              </div>
              <div v-else class="sim-actual-empty">预填了该策略的五元组,点击"预演"查看流量在节点规则集内的实际走向</div>
            </div>
          </el-col>
        </el-row>
      </div>
    </el-drawer>

    <!-- 从模板实例化 -->
    <el-dialog v-model="instantiateVisible" title="从模板实例化" width="480px">
      <el-form label-width="90px">
        <el-form-item label="选择模板">
          <el-select v-model="instantiateForm.template_id" placeholder="模板" style="width: 100%">
            <el-option v-for="t in templates" :key="t.id" :label="`${t.name} (${t.action}, ${t.protocol || 'ANY'})`" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="实例名称"><el-input v-model="instantiateForm.name" placeholder="空则用模板名" /></el-form-item>
        <el-form-item v-if="isMarkTpl" label="源地址">
          <el-input v-model="instantiateForm.source" placeholder="白名单 IP/CIDR,如 192.168.1.5" />
        </el-form-item>
        <el-form-item v-if="isMarkTpl" label="源地址组">
          <el-select v-model="instantiateForm.source_group" clearable placeholder="白名单地址组(与源地址二选一)" style="width: 100%">
            <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="立即应用"><el-switch v-model="instantiateForm.apply" /></el-form-item>
        <span class="form-hint">实例化时从模板全量复制参数,之后模板修改不影响本实例</span>
      </el-form>
      <template #footer>
        <el-button @click="instantiateVisible = false">取消</el-button>
        <el-button type="primary" @click="handleInstantiate" :loading="instantiating">实例化</el-button>
      </template>
    </el-dialog>

    <!-- 新建/编辑策略(共用表单) -->
    <el-dialog v-model="formVisible" :title="isCreate ? '新建策略' : '编辑实例参数'" width="640px">
      <el-form :model="instForm" label-width="90px">
        <el-form-item label="实例名称"><el-input v-model="instForm.name" /></el-form-item>
        <el-form-item v-if="instForm.action !== 'MARK'" label="所属组">
          <el-select v-model="instForm.group_id" style="width: 100%">
            <el-option v-for="cc in customChains" :key="cc.id" :label="`${cc.name}${cc.description ? ' - ' + cc.description : ''}`" :value="cc.id" />
          </el-select>
        </el-form-item>
        <div class="form-row">
          <el-form-item label="源地址" class="form-col"><el-input v-model="instForm.source" :placeholder="instForm.action === 'MARK' ? '白名单 IP/CIDR,如 192.168.1.5' : '空=任意'" /></el-form-item>
          <el-form-item v-if="instForm.action !== 'MARK'" label="目标地址" class="form-col"><el-input v-model="instForm.destination" placeholder="空=任意" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="源地址组" class="form-col">
            <el-select v-model="instForm.source_group" clearable :placeholder="instForm.action === 'MARK' ? '白名单地址组(与源地址二选一)' : '空=不匹配组'" style="width: 100%">
              <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="instForm.action !== 'MARK'" label="目的地址组" class="form-col">
            <el-select v-model="instForm.destination_group" clearable placeholder="空=不匹配组" style="width: 100%">
              <el-option v-for="ag in addressGroups" :key="ag.id" :label="ag.name" :value="ag.name" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="协议" class="form-col">
            <el-select v-model="instForm.protocol" style="width: 100%"><el-option label="任意" value="ANY" /><el-option label="TCP" value="TCP" /><el-option label="UDP" value="UDP" /><el-option label="ICMP" value="ICMP" /></el-select>
          </el-form-item>
          <el-form-item label="端口范围" class="form-col"><el-input v-model="instForm.port_range" placeholder="如 80 或 1000:2000" /></el-form-item>
        </div>
        <el-form-item label="动作">
          <el-select v-model="instForm.action" style="width: 100%">
            <el-option-group label="流量控制">
              <el-option label="允许 ACCEPT" value="ACCEPT" />
              <el-option label="丢弃 DROP" value="DROP" />
              <el-option label="拒绝 REJECT" value="REJECT" />
            </el-option-group>
            <el-option-group label="地址转换">
              <el-option label="目的转换 DNAT" value="DNAT" />
              <el-option label="源转换 SNAT" value="SNAT" />
            </el-option-group>
            <el-option-group label="白名单拦截">
              <el-option label="端口白名单拦截 MARK" value="MARK" />
            </el-option-group>
          </el-select>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'MARK'" label="流量方向">
          <el-select v-model="instForm.direction" style="width: 100%">
            <el-option label="容器转发(Docker 端口映射)" value="FORWARD" />
            <el-option label="主机入站(本地服务)" value="INPUT" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'MARK'" label="标记值">
          <el-select v-model="instForm.mark" style="width: 100%" placeholder="选标记(标记管理中维护)">
            <el-option v-for="m in marks" :key="m.id" :label="`${m.name} (${m.value})`" :value="m.value" />
          </el-select>
          <span class="form-hint">选方向+源(地址或组)+端口+标记值,自动生成:打标 -> 白名单放行 -> 其余丢弃</span>
        </el-form-item>
        <el-form-item v-if="instForm.action === 'DNAT' || instForm.action === 'SNAT'" label="NAT 目标"><el-input v-model="instForm.nat_to" placeholder="如 1.2.3.4 或 1.2.3.4:8080" /></el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="instForm.priority" style="width: 100%" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="instForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="instForm.enabled" /></el-form-item>
        <el-form-item v-if="isCreate" label="立即应用"><el-switch v-model="instForm.apply" /></el-form-item>
      </el-form>
      <div class="cmd-preview">
        <div class="cmd-preview-head">规则预览</div>
        <pre class="cmd-preview-code"><span v-for="(line, i) in previewCommand" :key="i" :class="'cmd-' + line.type">{{ line.text }}{{ i < previewCommand.length - 1 ? '\n' : '' }}</span></pre>
      </div>
      <template #footer>
        <el-button @click="formVisible = false">取消</el-button>
        <el-button type="primary" @click="saveInst" :loading="savingInst">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, VideoPlay } from '@element-plus/icons-vue'
import ExpertMode from './ExpertMode.vue'
import { getNodes, getNodeInstances, createInstance, updateInstance, deleteInstance, syncInstance, syncInstancePreview, syncAllNode, dispatchNode, getTemplates, getCustomChains, getAddressGroups, getMarks, getTasks, getTask, simulateFlow, getNodeRuleHits } from '@/api'
import { buildCommandPreview } from '@/composables/useCommandPreview'
import { usePolling } from '@/composables/usePolling'
import { useGuardStore } from '@/stores/guard'

const route = useRoute()
const guard = useGuardStore()
const guardTask = ref(null) // 该节点保护期待确认任务(跳转来时高亮提示)
const inflightTasks = ref([]) // 该节点在途任务:confirm_wait(可接管)/dispatching/applying(执行中)
const recentSuperseded = ref(null) // 该节点最近被接管(合并)的旧任务(保护期动作合并接管)

// 节点是否有保护期待确认任务(新动作已下发,未确认前处于保护期)
const nodeInGuard = computed(() => inflightTasks.value.some((t) => t.status === 'confirm_wait'))
// 节点是否有执行中任务(Agent 正在 Apply,不可接管,操作按钮禁用)
const nodeBusy = computed(() => inflightTasks.value.some((t) => t.status === 'dispatching' || t.status === 'applying'))

// 刷新该节点在途任务与最近被接管任务。保护期动作合并接管:操作后旧任务被 superseded、
// 新任务进 confirm_wait,banner/状态标签据此提示"动作已接管/保护期内"。
const refreshInflight = async () => {
  if (!selectedNodeId.value) return
  try {
    const [cw, disp, app, sup] = await Promise.all([
      getTasks({ status: 'confirm_wait' }),
      getTasks({ status: 'dispatching' }),
      getTasks({ status: 'applying' }),
      getTasks({ status: 'superseded' }),
    ])
    const nid = selectedNodeId.value
    inflightTasks.value = [...(cw.tasks || []), ...(disp.tasks || []), ...(app.tasks || [])].filter((t) => t.node_id === nid)
    // recentSuperseded 仅取最近 10 分钟内被接管的任务(updated_at = 置 superseded 时刻),
    // 接管提示完成后自动消失,避免历史 superseded 残留致 banner 永久显示。
    const tenMinAgo = Date.now() - 10 * 60 * 1000
    recentSuperseded.value = (sup.tasks || []).find((t) => t.node_id === nid && new Date(t.updated_at).getTime() >= tenMinAgo) || null
    guardTask.value = (cw.tasks || []).find((t) => t.node_id === nid) || null
  } catch {
    // 在途任务刷新失败不阻塞实例展示
  }
}

// 本次操作涉及、需保护期确认的实例意图 Map(id -> 'dispatch'|'remove'):
// 操作后记录,实例条目显示"⏳ 下发待确认/移除待确认"标签,把接管/待确认提示定位到
// 具体策略条目。基于操作意图而非 inst.enabled 可变值——toggleEnabled 乐观翻转后
// loadInstances 会刷新实例,若用 enabled 判断,标签可能与被执行操作错位
// (如禁用后 enabled 被并发刷新覆盖为 true,标签误显"下发待确认")。保护期结束后清空。
const pendingConfirmIntents = ref(new Map())
const markPendingConfirm = (id, intent) => {
  const m = new Map(pendingConfirmIntents.value)
  m.set(id, intent)
  pendingConfirmIntents.value = m
}
watch(nodeInGuard, (g) => { if (!g) pendingConfirmIntents.value = new Map() })

// 在途任务存在时轮询(Bug1 修复):任务执行(dispatching/applying)完成后自动解除
// nodeBusy 按钮禁用(无需手动刷新),保护期(confirm_wait)确认/回滚后自动收敛;
// 无任务时停止轮询,避免 4 个 getTasks 空转请求。
usePolling(refreshInflight, 5000, () => inflightTasks.value.length > 0)

const nodesLoading = ref(false)
const instLoading = ref(false)
const dispatching = ref(false)
const nodes = ref([])
const instances = ref([])
const ruleHitsMap = ref({}) // 规则命中率(规则活性分析):instance_id -> {packets,bytes,dead,last_seen}
const onlyDead = ref(false) // 仅看死规则过滤

// 排序:未下发(enabled && !applied)或待移除(!enabled && applied)置顶,其次按添加时间倒序(新在上)
const sortedInstances = computed(() => {
  let list = [...instances.value]
  if (onlyDead.value) {
    list = list.filter((i) => ruleHitsMap.value[i.id]?.dead)
  }
  return list.sort((a, b) => {
    const ap = (a.enabled && !a.applied) || (!a.enabled && a.applied) ? 0 : 1
    const bp = (b.enabled && !b.applied) || (!b.enabled && b.applied) ? 0 : 1
    if (ap !== bp) return ap - bp
    return new Date(b.created_at) - new Date(a.created_at)
  })
})
const templates = ref([])
const customChains = ref([])
const addressGroups = ref([])
const marks = ref([])
const selectedNodeId = ref('')
const expertMode = ref(false)

const currentNodeLabel = computed(() => {
  const n = nodes.value.find(x => x.id === selectedNodeId.value)
  return n ? (n.ip || n.hostname || n.id.slice(0, 12)) : '未选择'
})

const getActionLabel = (a) => ({ ACCEPT: '允许', DROP: '丢弃', REJECT: '拒绝', MARK: '白名单拦截', DNAT: 'DNAT', SNAT: 'SNAT' }[a] || a || '-')

// 编辑对话框命令预览:响应式跟踪 instForm 与 customChains
const previewCommand = computed(() => buildCommandPreview(instForm, customChains.value))

// 轮询 task 直到终态(confirm_wait/confirmed/failed/rolled_back)或超时(15s)。
// 后端 dispatch 异步:Send 后 task 处于 applying,Agent 回 TaskResult 后才更新 applied。
// 不轮询会因 applied 延迟导致前端显示"未下发"而规则实际已生效。
const pollTaskDone = async (taskID) => {
  const terminal = new Set(['confirm_wait', 'confirmed', 'failed', 'rolled_back'])
  for (let i = 0; i < 15; i++) {
    await new Promise(r => setTimeout(r, 1000))
    try {
      const t = await getTask(taskID)
      if (terminal.has(t.status)) return t
    } catch {}
  }
  return null
}

// 一键启停:切换实例 enabled 后自动下发。
// 乐观更新(F2):先翻转 UI 即时反馈,后台写库+下发+收敛;失败回滚乐观值。
// 原实现串行等待 pollTaskDone(15s),高频启停无即时反馈。保护期提示由
// refreshInflight 刷新 inflightTasks 后顶部 banner 呈现,不再阻塞等待终态。
const toggleEnabled = async (inst, v) => {
  const prev = inst.enabled
  inst.enabled = v // 乐观翻转:UI 立即响应,后台收敛
  try {
    await updateInstance(inst.id, { ...inst, enabled: v })
    await dispatchNode(selectedNodeId.value, { auto_approve: true })
    ElMessage.success((v ? '启用' : '禁用') + '动作已下发,保护期确认见顶部')
    markPendingConfirm(inst.id, v ? 'dispatch' : 'remove') // 该实例下发/移除待确认,条目上打标定位
    loadInstances()
    refreshInflight()
    guard.refresh() // 待确认区立即刷新(不等 5s 轮询)
  } catch (e) {
    inst.enabled = prev // 失败回滚乐观值
    // 409:节点有任务执行中,不可接管(执行中任务不可作废)。实例已改 DB 但未下发,提示稍候重试
    ElMessage.error(e?.response?.data?.error || '切换失败')
    loadInstances()
    refreshInflight()
  }
}

const loadNodes = async () => {
  nodesLoading.value = true
  try {
    const d = await getNodes()
    nodes.value = d.nodes || []
  } catch {
    ElMessage.error('加载节点失败')
  } finally {
    nodesLoading.value = false
  }
}

const loadInstances = async () => {
  if (!selectedNodeId.value) return
  instLoading.value = true
  try {
    const d = await getNodeInstances(selectedNodeId.value)
    instances.value = d.instances || []
    loadRuleHits() // 加载规则命中率(规则活性分析),不阻塞实例展示
  } catch {
    ElMessage.error('加载实例失败')
  } finally {
    instLoading.value = false
  }
}

// 规则活性分析:加载节点规则命中率 + 死规则标记
const loadRuleHits = async () => {
  if (!selectedNodeId.value) return
  try {
    const d = await getNodeRuleHits(selectedNodeId.value)
    const m = {}
    for (const h of (d.hits || [])) {
      m[h.instance_id] = h
    }
    ruleHitsMap.value = m
  } catch {
    // 命中率加载失败不阻塞(可能 Agent 未上报)
  }
}

// 格式化命中率显示
const formatHits = (h) => {
  if (!h || !h.last_seen) return '未采集'
  return `${h.packets} 包 / ${formatBytes(h.bytes)}`
}
const formatBytes = (b) => {
  if (!b) return '0 B'
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  return (b / 1048576).toFixed(1) + ' MB'
}

const loadDeps = async () => {
  try {
    const [t, c, ag, mk] = await Promise.all([getTemplates(), getCustomChains(), getAddressGroups(), getMarks()])
    templates.value = t.templates || []
    customChains.value = c.custom_chains || c.chains || []
    addressGroups.value = ag.address_groups || []
    marks.value = mk.marks || []
  } catch {
    // 依赖加载失败不阻塞
  }
}

const selectNode = (n) => {
  selectedNodeId.value = n.id
  loadInstances()
  refreshInflight()
}

// 单条策略流量预演(计划二):五元组仿真,预期目标 vs 实际命中路径
const simVisible = ref(false)
const simLoading = ref(false)
const simResult = ref(null)
const simInst = ref(null)
const simForm = reactive({ direction: 'FORWARD', source_ip: '', dest_ip: '', protocol: 'tcp', src_port: 0, dst_port: 0, mark: 0 })

// 从实例反推五元组:CIDR 取首个 IP / 端口区间取最小值
const pickFirstIp = (cidr) => (cidr ? cidr.split('/')[0] : '')
const parseFirstPort = (range) => {
  if (!range) return 0
  const p = parseInt(range.split('-')[0], 10)
  return Number.isNaN(p) ? 0 : p
}

// 推断方向:按实例所属组链挂载(parent)推断,兜底 FORWARD
const inferDirection = (inst) => {
  const cc = customChains.value.find((c) => String(c.id) === String(inst.group_id))
  const mounts = cc?.mount_list || cc?.mounts || []
  const candidates = [...mounts.map((m) => m.parent), cc?.parent].filter(Boolean)
  for (const p of candidates) {
    const up = String(p).toUpperCase()
    if (up.includes('INPUT')) return 'INPUT'
    if (up.includes('FORWARD')) return 'FORWARD'
    if (up.includes('OUTPUT')) return 'OUTPUT'
  }
  return 'FORWARD'
}

const openInstSimulate = (inst) => {
  simInst.value = inst
  simForm.direction = inferDirection(inst)
  simForm.source_ip = inst.source_group ? '' : pickFirstIp(inst.source)
  simForm.dest_ip = inst.destination || ''
  simForm.protocol = (inst.protocol || 'tcp').toLowerCase()
  simForm.dst_port = parseFirstPort(inst.port_range)
  simForm.src_port = 0
  simForm.mark = 0
  simResult.value = null
  simVisible.value = true
}

// 预期目标文案(左侧"你的预期目标")
const expectedText = (inst) => {
  const a = (inst.action || '').toUpperCase()
  if (a === 'MARK') return '打标后由 MARKACL 白名单链放行;非白名单源将兜底 DROP'
  if (a === 'ACCEPT') return '该流量将被放行(ACCEPT)'
  if (a === 'DROP') return '该流量将被拦截(DROP)'
  if (a === 'REJECT') return '该流量将被拒绝(REJECT)'
  return a || '—'
}

// 命中终止的 step 索引(DROP/REJECT 终止位置)
const hitStopIndex = computed(() => {
  if (!simResult.value?.steps?.length) return -1
  let idx = -1
  simResult.value.steps.forEach((s, i) => { if (s.matched) idx = i })
  return idx
})
const isTerminalStep = (i) => {
  const v = simResult.value?.verdict
  return (v === 'DROP' || v === 'REJECT') && i === hitStopIndex.value
}
const nodeTagType = (s) => ({ MARK: 'info', ACCEPT: 'success', DROP: 'danger', REJECT: 'warning' }[s.action] || 'info')

// 判定横幅元信息:图标 + 中文标签
const verdictMeta = computed(() => {
  const v = simResult.value?.verdict || ''
  const map = {
    ACCEPT: { icon: '✓', label: '流量将被放行' },
    DROP: { icon: '✕', label: '流量将被拦截' },
    REJECT: { icon: '⚠', label: '流量将被拒绝' },
    PASS: { icon: '→', label: '未命中任何规则,默认策略放行' },
  }
  return map[v] || { icon: '?', label: '' }
})

const handleSimulate = async () => {
  if (!selectedNodeId.value) return
  simLoading.value = true
  simResult.value = null
  try {
    const d = await simulateFlow({
      node_id: selectedNodeId.value,
      flow: { ...simForm },
    })
    simResult.value = d
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '预演失败')
  } finally {
    simLoading.value = false
  }
}

// 从模板实例化
const instantiateVisible = ref(false)
const instantiating = ref(false)
const instantiateForm = reactive({ template_id: null, name: '', apply: true, source: '', source_group: '' })
// 选中模板是否 MARK 白名单(无源骨架,实例化时需补源)
const selectedTpl = computed(() => templates.value.find((t) => t.id === instantiateForm.template_id))
const isMarkTpl = computed(() => selectedTpl.value?.action === 'MARK')
const openInstantiate = () => {
  instantiateForm.template_id = null
  instantiateForm.name = ''
  instantiateForm.apply = true
  instantiateForm.source = ''
  instantiateForm.source_group = ''
  instantiateVisible.value = true
}
const handleInstantiate = async () => {
  if (!instantiateForm.template_id) { ElMessage.warning('请选模板'); return }
  // MARK 白名单模板无源骨架,实例化时必须补源(实例层 requireMarkSource 校验)
  if (isMarkTpl.value && !instantiateForm.source && !instantiateForm.source_group) {
    ElMessage.warning('请填源地址或源地址组(白名单)')
    return
  }
  instantiating.value = true
  try {
    await createInstance(selectedNodeId.value, {
      template_id: instantiateForm.template_id,
      name: instantiateForm.name,
      apply: instantiateForm.apply,
      source: instantiateForm.source,
      source_group: instantiateForm.source_group,
    })
    ElMessage.success('已实例化' + (instantiateForm.apply ? '并下发' : ''))
    instantiateVisible.value = false
    loadInstances()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '实例化失败')
  } finally {
    instantiating.value = false
  }
}

// 新建/编辑策略(共用表单):isCreate 区分新建(POST 完整参数,template_id=0)与编辑(PUT 更新)
const formVisible = ref(false)
const savingInst = ref(false)
const isCreate = ref(false)
const defaultForm = () => ({
  template_id: 0, name: '', group_id: 0, direction: 'FORWARD', source: '', destination: '',
  source_group: '', destination_group: '', protocol: 'ANY',
  port_range: '', action: 'ACCEPT', mark: 0, nat_to: '',
  match_mark: 0, priority: 50, description: '', enabled: true, apply: false
})
const instForm = reactive(defaultForm())
// 动作切换时清理关联字段:MARK 不需要组/链,非 MARK 不需要方向
watch(() => instForm.action, (action) => {
  if (action === 'MARK') {
    instForm.group_id = 0
    if (!instForm.direction) instForm.direction = 'FORWARD'
  } else {
    instForm.direction = ''
  }
})
const openCreate = () => {
  isCreate.value = true
  Object.assign(instForm, defaultForm())
  instForm.direction = instForm.action === 'MARK' ? 'FORWARD' : ''
  formVisible.value = true
}
const openEditInst = (inst) => {
  isCreate.value = false
  Object.assign(instForm, defaultForm(), inst)
  formVisible.value = true
}
const saveInst = async () => {
  if (!instForm.name) { ElMessage.warning('请填实例名称'); return }
  // MARK 白名单拦截:方向+源地址组+端口+标记值;其他动作需选策略组
  if (instForm.action === 'MARK') {
    if (!instForm.source && !instForm.source_group) { ElMessage.warning('请填源地址或源地址组(白名单)'); return }
    if (!instForm.port_range) { ElMessage.warning('请填端口'); return }
    if (!instForm.mark) { ElMessage.warning('请选标记值'); return }
  } else {
    if (!instForm.group_id) { ElMessage.warning('请选策略组'); return }
  }
  // 匹配标记入口已移除(仅 MARK 打标保留),强制清零避免旧实例残留 match_mark
  instForm.match_mark = 0
  savingInst.value = true
  try {
    if (isCreate.value) {
      await createInstance(selectedNodeId.value, instForm)
      ElMessage.success('已新建' + (instForm.apply ? '并下发' : ''))
    } else {
      await updateInstance(instForm.id, instForm)
      ElMessage.success('已保存')
    }
    formVisible.value = false
    loadInstances()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '保存失败')
  } finally {
    savingInst.value = false
  }
}

const handleSync = async (inst) => {
  try {
    // 先调预览接口拿字段级 diff,展示"将覆盖什么"再确认(降低手动同步认知负担)
    let diffText = '将同步模板最新参数'
    try {
      const p = await syncInstancePreview(inst.id)
      const fields = p.fields || []
      if (fields.length) {
        diffText = '将覆盖以下字段:<br>' + fields
          .map((f) => `· ${f.label}: ${f.current || '(空)'} → ${f.template || '(空)'}`)
          .join('<br>') + '<br><span style="color:#909399">模板空值字段保留实例当前值(如源 IP),不被覆盖</span>'
      } else {
        diffText = '实例与模板当前参数一致,无需同步'
      }
    } catch { /* 预览失败不阻塞,仍可确认 */ }
    await ElMessageBox.confirm(`同步实例「${inst.name}」?<br>${diffText}`, '确认同步', {
      type: 'warning', dangerouslyUseHTMLString: true, confirmButtonText: '同步', cancelButtonText: '取消'
    })
    await syncInstance(inst.id)
    ElMessage.success('已同步')
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('同步失败')
  }
}

// 字段中文名映射:实例与模板参数 diff 的 tooltip 展示
const fieldLabels = { group_id: '所属策略组', direction: '流量方向', source: '源地址', destination: '目的地址', protocol: '协议', port_range: '端口', action: '动作', mark: '标记', nat_to: '转换目标', source_group: '源地址组', destination_group: '目的地址组', match_mark: '匹配标记', priority: '优先级' }
const driftFieldsText = (inst) => {
  const f = inst.deviated_fields || inst.drift_fields || []
  if (!f.length) return '与模板参数一致'
  return '与模板不一致: ' + f.map((x) => fieldLabels[x] || x).join('、')
}

// 批量同步:一键把当前节点所有漂移实例同步为模板最新参数
const syncingAll = ref(false)
const driftInstanceCount = computed(() => instances.value.filter((i) => i.drift).length)
const handleSyncAll = async () => {
  const n = driftInstanceCount.value
  if (!n) { ElMessage.info('没有待同步的漂移实例'); return }
  try {
    await ElMessageBox.confirm(`将把当前节点 ${n} 个漂移实例同步为模板最新参数. 手动修改过的实例参数将被覆盖, 同步后需重新下发生效.`, '确认批量同步', { type: 'warning', confirmButtonText: '同步', cancelButtonText: '取消' })
    syncingAll.value = true
    const d = await syncAllNode(selectedNodeId.value)
    ElMessage.success(`已同步 ${d.synced} 个实例, 跳过 ${d.skipped} 个`)
    loadInstances()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.response?.data?.error || '批量同步失败')
  } finally {
    syncingAll.value = false
  }
}

const handleDeleteInst = async (inst) => {
  try {
    await ElMessageBox.confirm(`移除实例「${inst.name}」?若已下发将进入保护期,可回滚.`, '确认移除', { type: 'warning', confirmButtonText: '移除', cancelButtonText: '取消' })
    const data = await deleteInstance(inst.id)
    if (data && data.task_id) {
      // 202:节点有规则,已下发移除并进保护期,轮询终态
      ElMessage.info('已移除并进入保护期,可在保护期面板确认或回滚')
      markPendingConfirm(inst.id, 'remove') // 移除待确认,条目上打标定位
      const t = await pollTaskDone(data.task_id)
      if (t && t.status === 'failed') {
        ElMessage.error('移除下发失败,实例已恢复')
      }
      loadInstances()
      guard.refresh()
    } else {
      // 204:节点无规则,直接删除
      ElMessage.success('已移除')
      loadInstances()
    }
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.response?.data?.error || '移除失败')
  }
}

const handleDispatch = async () => {
  // 后端 dispatch 为全量同步语义(编译节点所有 enabled 实例,Agent 全量重建链)。
  // 无待变更时跳过,避免无意义的全量重建;有变更时提示全量对齐。
  const pending = instances.value.filter(i => i.enabled && !i.applied)
  const disabling = instances.value.filter(i => !i.enabled && i.applied)
  if (!pending.length && !disabling.length) {
    ElMessage.info('没有待下发的策略变更,节点已与配置对齐,无需下发')
    return
  }
  dispatching.value = true
  try {
    const d = await dispatchNode(selectedNodeId.value, { auto_approve: true })
    const taskID = d.tasks?.[0]?.id
    if (!taskID) { ElMessage.warning('未创建任务'); return }
    const t = await pollTaskDone(taskID)
    if (!t) { ElMessage.warning('下发超时,请稍后查看'); loadInstances(); refreshInflight(); return }
    if (t.status === 'confirm_wait') {
      // 保护期动作合并接管:旧任务已被作废,新动作进保护期
      ElMessage.success('已下发,动作接管保护期,请到顶部确认')
      // 全量对齐:本次涉及全部启用实例统一标记"下发待确认"
      for (const i of instances.value.filter((x) => x.enabled)) markPendingConfirm(i.id, 'dispatch')
    } else if (t.status === 'confirmed') {
      ElMessage.success('已下发并确认')
    } else {
      ElMessage.error('下发失败: ' + (t.message || t.status))
    }
    loadInstances()
    refreshInflight()
    guard.refresh() // 待确认区立即刷新(不等 5s 轮询)
  } catch (e) {
    // 409:节点有任务执行中,不可接管
    ElMessage.error(e?.response?.data?.error || '下发失败')
    refreshInflight()
  } finally {
    dispatching.value = false
  }
}

onMounted(async () => {
  await loadNodes()
  loadDeps()
  if (route.query.node) {
    const n = nodes.value.find((x) => x.id === route.query.node)
    if (n) selectNode(n)
    refreshInflight()
  }
})

// 保护期面板确认/回滚后(guard.refresh)刷新在途任务:banner/状态标签据此更新接管提示
watch(() => guard.refreshTick, refreshInflight)

// 页面已加载时从保护期跳转也能选中节点 + 显示 banner
watch(() => route.query.node, async (nodeId) => {
  if (!nodeId) { guardTask.value = null; inflightTasks.value = []; recentSuperseded.value = null; return }
  if (!nodes.value.length) return
  const n = nodes.value.find((x) => x.id === nodeId)
  if (n) selectNode(n)
  refreshInflight()
})

// 暴露供单测/编程式调用(乐观更新行为验证)
defineExpose({ toggleEnabled, loadInstances, refreshInflight })
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.guard-banner { margin-bottom: 12px; cursor: pointer; font-weight: 500; }
.guard-banner-main { margin-bottom: 4px; }
.guard-banner-diff { margin: 0; padding: 8px; background: rgba(0,0,0,.04); border-radius: 6px; font-size: 11px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow: auto; color: #7a5a00; }
.header-left { display: flex; align-items: center; gap: 12px; }
.page-title { font-size: 18px; font-weight: 600; color: var(--c-text-1, #1e293b); margin: 0; }
.np-body { min-height: 480px; }
.node-card, .inst-card { height: 100%; }
.empty-mini { text-align: center; color: var(--c-text-3); padding: 24px 0; font-size: 13px; }
.node-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; font-size: 13px; }
.node-item:hover { background: var(--c-surface-2, #f5f7fa); }
.node-item.active { background: var(--c-primary-soft, #e0f2fe); color: var(--c-primary, #2563eb); font-weight: 600; }
.node-ip { font-family: 'Courier New', monospace; }
.inst-head { display: flex; justify-content: space-between; align-items: center; }
.inst-actions { display: flex; gap: 8px; }
.inst-list { display: flex; flex-direction: column; gap: 10px; }
.inst-item { border: 1px solid var(--c-border); border-radius: 12px; padding: 14px 16px; background: var(--c-surface); box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.04); transition: box-shadow var(--transition), border-color var(--transition); }
.inst-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.08); border-color: var(--c-border-hover); }
.inst-item.drift { border-color: var(--c-warning); background: rgba(251,191,36,0.08); }
.inst-item.not-applied { border-left: 3px solid var(--c-warning); }
.inst-item.disabled { opacity: .55; border-left: 3px solid var(--c-danger); background: rgba(0,0,0,0.02); }
.inst-item.disabled .inst-name { text-decoration: line-through; color: var(--c-text-3); }
.inst-top { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
.inst-name { font-weight: 600; color: #1e293b; }
.inst-rule { display: flex; align-items: center; gap: 14px; font-size: 13px; color: var(--c-text-2); flex-wrap: wrap; }
.field .lbl { color: var(--c-text-3); margin-right: 4px; }
.action { margin-left: auto; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: var(--c-bg); }
.action.accept { color: #16a34a; background: #dcfce7; }
.action.drop { color: #dc2626; background: #fee2e2; }
.action.reject { color: #d97706; background: #fef3c7; }
.action.mark { color: #2563eb; background: #dbeafe; }
.inst-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--c-bg); }
.inst-cmd { margin-top: 8px; padding: 6px 8px; background: var(--c-bg); border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; }
.inst-cmd code { display: block; white-space: pre-wrap; word-break: break-all; color: var(--c-text-3); line-height: 1.6; }
.foot-left { display: flex; align-items: center; gap: 10px; }
.prio { font-size: 12px; color: var(--c-text-3); }
.hits { font-size: 12px; color: var(--c-text-3); }
.dead-filter { margin-left: 8px; }
.cmd-preview { margin-top: 12px; }
.cmd-preview-head { font-size: 12px; color: #64748b; margin-bottom: 6px; }
.cmd-preview-code { background: var(--c-surface); color: var(--c-text-1); padding: 10px; border-radius: 6px; font-size: 12px; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; margin: 0; }
.cmd-mark { color: #60a5fa; }
.cmd-accept { color: #4ade80; }
.cmd-drop { color: #f87171; }
.actions { display: flex; gap: 4px; }
.form-row { display: flex; gap: 12px; }
.form-col { flex: 1; }
.form-hint { display: block; margin-top: -8px; padding-left: 90px; font-size: 12px; color: var(--c-text-3); }

/* 单条策略流量预演:抽屉布局 + 判定横幅 + 垂直步骤流(命令代码块) */
.sim-layout { display: flex; flex-direction: column; gap: 14px; height: 100%; }
.sim-form-bar { display: flex; flex-direction: column; gap: 6px; padding: 12px; border: 1px solid var(--el-border-color-light); border-radius: 8px; background: var(--c-surface); }
.sim-fields { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sim-form-hint { font-size: 12px; color: var(--c-text-3); }
.sim-body { flex: 1; min-height: 0; margin-top: 0 !important; }
.sim-panel { height: 100%; border: 1px solid var(--el-border-color-light); border-radius: 8px; padding: 14px; background: var(--c-surface); }
.sim-panel-title { font-size: 13px; font-weight: 600; color: var(--c-text-1); margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px dashed var(--el-border-color-lighter); }

/* 判定横幅:大图标 + verdict + 自然语言结论 */
.sim-verdict-banner {
  display: flex; align-items: center; gap: 14px;
  padding: 14px 18px; border-radius: 10px; border: 1px solid var(--el-border-color);
}
.verdict-accept { background: linear-gradient(135deg, #f0fdf4, #ecfdf5); border-color: rgba(22, 163, 74, .4); }
.verdict-drop { background: linear-gradient(135deg, #fef2f2, #fff1f2); border-color: rgba(220, 38, 38, .4); }
.verdict-reject { background: linear-gradient(135deg, #fffbeb, #fef3c7); border-color: rgba(217, 119, 6, .4); }
.verdict-pass { background: linear-gradient(135deg, #f8fafc, #f1f5f9); border-color: var(--el-border-color); }
.verdict-icon {
  width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 22px; font-weight: 800; color: #fff;
}
.verdict-accept .verdict-icon { background: #16a34a; }
.verdict-drop .verdict-icon { background: #dc2626; }
.verdict-reject .verdict-icon { background: #d97706; }
.verdict-pass .verdict-icon { background: #94a3b8; }
.verdict-main { flex: 1; min-width: 0; }
.verdict-title { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.verdict-tag { font-family: 'Courier New', monospace; font-weight: 800; font-size: 18px; letter-spacing: 1px; }
.verdict-accept .verdict-tag { color: #16a34a; }
.verdict-drop .verdict-tag { color: #dc2626; }
.verdict-reject .verdict-tag { color: #d97706; }
.verdict-pass .verdict-tag { color: #64748b; }
.verdict-label { font-size: 13px; color: var(--c-text-2); }
.verdict-conclusion { font-size: 13px; color: var(--c-text-1); line-height: 1.7; }

/* 左侧:预期目标 */
.expected-detail { font-size: 13px; color: var(--c-text-2); }
.exp-row { display: flex; gap: 8px; margin-bottom: 6px; }
.exp-lbl { width: 42px; color: var(--c-text-3); flex-shrink: 0; }
.exp-action { font-weight: 600; }
.exp-action.accept { color: #16a34a; }
.exp-action.drop { color: #dc2626; }
.exp-action.reject { color: #d97706; }
.exp-action.mark { color: #2563eb; }
.expected-verdict { margin-top: 10px; padding: 8px 10px; border-radius: 6px; background: var(--c-bg); font-size: 12px; color: var(--c-text-2); line-height: 1.6; }

/* 右侧:垂直步骤流(时间轴 + 命中高亮 + 命令代码块) */
.sim-actual-empty { font-size: 13px; color: var(--c-text-3); text-align: center; padding: 40px 0; }
.sim-steps { display: flex; flex-direction: column; gap: 10px; padding: 4px 0; }
.sim-step-entry {
  align-self: flex-start; font-size: 11px; color: var(--c-text-3);
  border: 1px dashed var(--el-border-color); border-radius: 999px; padding: 3px 12px;
}
.sim-step-end { font-weight: 700; border-style: solid; }
.end-accept { color: #16a34a; border-color: rgba(22, 163, 74, .5); background: #f0fdf4; }
.end-drop { color: #dc2626; border-color: rgba(220, 38, 38, .5); background: #fef2f2; }
.end-reject { color: #d97706; border-color: rgba(217, 119, 6, .5); background: #fffbeb; }
.end-pass { color: #64748b; }

.sim-step { display: flex; gap: 10px; }
.step-rail { position: relative; width: 14px; flex-shrink: 0; }
.step-rail::before {
  content: ''; position: absolute; left: 6px; top: 0; bottom: 0; width: 2px;
  background: var(--el-border-color-lighter);
}
.sim-step:first-of-type .step-rail::before { top: 12px; }
.sim-step:last-of-type .step-rail::before { bottom: auto; }
.step-dot {
  position: absolute; left: 2px; top: 12px; width: 12px; height: 12px; border-radius: 50%;
  background: #fff; border: 2px solid var(--el-border-color); z-index: 1;
}
.sim-step.hit .step-dot { background: #3b82f6; border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59, 130, 246, .18); }
.sim-step.term .step-dot { background: #dc2626; border-color: #dc2626; box-shadow: 0 0 0 4px rgba(220, 38, 38, .18); }

.step-body {
  flex: 1; min-width: 0; padding: 10px 12px; border: 1px solid var(--el-border-color-light);
  border-radius: 8px; background: #fff; opacity: .55; transition: all .25s;
}
.sim-step.hit .step-body { opacity: 1; border-color: #93c5fd; background: #f5f9ff; box-shadow: 0 0 0 1px #93c5fd inset; }
.sim-step.term .step-body { border-color: #fca5a5; background: #fff5f5; box-shadow: 0 0 0 1px #fca5a5 inset; }
.step-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
.step-chain { font-family: 'Courier New', monospace; font-size: 11px; color: #94a3b8; }
.step-action { font-weight: 700; font-size: 12px; }
.step-action.accept { color: #16a34a; }
.step-action.drop { color: #dc2626; }
.step-action.reject { color: #d97706; }
.step-action.mark { color: #2563eb; }
.step-action.dnat, .step-action.snat { color: #7c3aed; }
.step-rule { font-family: 'Courier New', monospace; font-size: 11px; color: var(--c-text-3); }
.step-term-badge {
  font-size: 10px; font-weight: 600; color: #dc2626;
  border: 1px solid rgba(220, 38, 38, .5); border-radius: 4px; padding: 0 5px;
}
/* 命令代码块(深色主题,命中步左边框高亮) */
.step-cmd {
  display: block; margin-top: 6px; padding: 7px 10px; border-radius: 6px;
  background: #1e1e2e; color: #cdd6f4; font-family: 'Courier New', monospace;
  font-size: 11px; line-height: 1.7; word-break: break-all; white-space: pre-wrap;
}
.sim-step.hit .step-cmd { border-left: 3px solid #34d399; }
.sim-step.term .step-cmd { border-left: 3px solid #f87171; }
.node-note { margin-top: 6px; font-size: 11px; color: #f59e0b; }

.sim-empty { font-size: 12px; color: var(--c-text-3); margin-top: 10px; }
</style>
