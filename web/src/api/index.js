import axios from 'axios'

const service = axios.create({
  baseURL: '/api',
  timeout: 15000
})

service.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

service.interceptors.response.use(
  (response) => {
    return response.data
  },
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('username')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// 认证
export const login = (data) => service.post('/v1/auth/login', data)
export const changePassword = (data) => service.post('/v1/auth/change-password', data)

// 节点管理
export const getNodes = () => service.get('/v1/nodes/list')
export const getNode = (id) => service.get(`/v1/nodes/${id}`)
export const updateNode = (id, data) => service.put(`/v1/nodes/${id}`, data)
export const deleteNode = (id) => service.delete(`/v1/nodes/${id}`)
export const createBootstrapToken = (data) => service.post('/v1/nodes/bootstrap', data)
export const approveNode = (id) => service.post(`/v1/nodes/${id}/approve`)
export const rejectNode = (id) => service.post(`/v1/nodes/${id}/reject`)
export const renewNodeCert = (id) => service.post(`/v1/nodes/${id}/renew-cert`)

// 策略管理(C 档):见下方 templates/instances API。旧 Policy CRUD 已废弃。

// 地址组(白/黑名单 IP 段集合)
export const getAddressGroups = () => service.get('/v1/address-groups')
export const getAddressGroup = (id) => service.get(`/v1/address-groups/${id}`)
export const createAddressGroup = (data) => service.post('/v1/address-groups', data)
export const updateAddressGroup = (id, data) => service.put(`/v1/address-groups/${id}`, data)
export const deleteAddressGroup = (id) => service.delete(`/v1/address-groups/${id}`)

export const getMarks = () => service.get('/v1/marks')
export const getMark = (id) => service.get(`/v1/marks/${id}`)
export const createMark = (data) => service.post('/v1/marks', data)
export const updateMark = (id, data) => service.put(`/v1/marks/${id}`, data)
export const deleteMark = (id) => service.delete(`/v1/marks/${id}`)

// 自定义链(业务子链 MYFW-<name>)
export const getCustomChains = () => service.get('/v1/custom-chains')
export const getCustomChain = (id) => service.get(`/v1/custom-chains/${id}`)
export const createCustomChain = (data) => service.post('/v1/custom-chains', data)
export const updateCustomChain = (id, data) => service.put(`/v1/custom-chains/${id}`, data)
export const deleteCustomChain = (id) => service.delete(`/v1/custom-chains/${id}`)

// 任务 / 审批管理
export const getTasks = (params) => service.get('/v1/tasks', { params })
export const getTask = (id) => service.get(`/v1/tasks/${id}`)
export const approveTask = (id, data) => service.post(`/v1/tasks/${id}/approve`, data || {})
export const rejectTask = (id, data) => service.post(`/v1/tasks/${id}/reject`, data || {})
export const confirmTask = (id) => service.post(`/v1/tasks/${id}/confirm`)
export const rollbackTask = (id) => service.post(`/v1/tasks/${id}/rollback`)

// 审计日志
export const getAuditLogs = (params) => service.get('/v1/audit/logs', { params })
export const exportAuditLogs = (params) => service.get('/v1/audit/export', { params, responseType: 'blob' })
export const getAuditDashboard = (days = 7) => service.get('/v1/audit/dashboard', { params: { days } })
export const getAuditConfidence = (days = 30) => service.get('/v1/audit/confidence', { params: { days } })

// 系统设置:日志/审批保留天数 + 手动清理异常数据
export const getRetention = () => service.get('/v1/system/retention')
export const updateRetention = (data) => service.put('/v1/system/retention', data)
export const cleanupNow = () => service.post('/v1/system/cleanup')

// 仪表盘
export const getDashboardStats = () => service.get('/v1/dashboard/stats')
export const getConfigDrift = () => service.get('/v1/dashboard/config-drift')

// iptables 规则
export const getNodeIptablesRules = (nodeId) => service.get(`/v1/iptables/rules/${nodeId}`)
export const operateNodeRule = (nodeId, op) => service.post(`/v1/iptables/rules/${nodeId}`, op)
export const getNodeDrift = (nodeId) => service.get(`/v1/iptables/drift/${nodeId}`)

// 专家模式:执行裸 iptables 命令(iptables 族),同步等待 Agent 回复
export const execIptables = (nodeId, command) => service.post(`/v1/iptables/exec/${nodeId}`, { command })

// 已连接节点
export const getConnectedNodes = () => service.get('/v1/nodes/connected')

// 策略模板库 + 节点策略实例 (C 档:模板/实例分离)
export const getTemplates = () => service.get('/v1/templates')
export const createTemplate = (data) => service.post('/v1/templates', data)
export const updateTemplate = (id, data) => service.put(`/v1/templates/${id}`, data)
export const deleteTemplate = (id) => service.delete(`/v1/templates/${id}`)
export const exportTemplates = () => service.get('/v1/templates/export')
export const importTemplates = (data) => service.post('/v1/templates/import', data)
export const getNodeInstances = (nodeId) => service.get(`/v1/nodes/${nodeId}/instances`)
export const createInstance = (nodeId, data) => service.post(`/v1/nodes/${nodeId}/instances`, data)
export const updateInstance = (id, data) => service.put(`/v1/instances/${id}`, data)
export const deleteInstance = (id) => service.delete(`/v1/instances/${id}`)
export const syncInstance = (id) => service.post(`/v1/instances/${id}/sync`)
export const syncInstancePreview = (id) => service.post(`/v1/instances/${id}/sync-preview`)
export const syncAllNode = (nodeId) => service.post(`/v1/nodes/${nodeId}/sync-all`)
export const dispatchNode = (nodeId, data) => service.post(`/v1/nodes/${nodeId}/dispatch`, data || {})

// 规则库版本档案(计划三:长期快照 + 任意时间点回滚)
export const getNodeRevisions = (nodeId) => service.get(`/v1/nodes/${nodeId}/revisions`)
export const rollbackRevision = (nodeId, revNo) => service.post(`/v1/nodes/${nodeId}/revisions/${revNo}/rollback`)

// 流量仿真预演(计划二:输入五元组,预演规则命中路径与最终判定)
export const simulateFlow = (data) => service.post('/v1/simulate', data)

// 规则活性分析:节点规则命中率(含死规则标记)
export const getNodeRuleHits = (nodeId) => service.get(`/v1/iptables/rule-hits/${nodeId}`)

export default service
