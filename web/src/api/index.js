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

// 仪表盘
export const getDashboardStats = () => service.get('/v1/dashboard/stats')

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
export const getNodeInstances = (nodeId) => service.get(`/v1/nodes/${nodeId}/instances`)
export const createInstance = (nodeId, data) => service.post(`/v1/nodes/${nodeId}/instances`, data)
export const updateInstance = (id, data) => service.put(`/v1/instances/${id}`, data)
export const deleteInstance = (id) => service.delete(`/v1/instances/${id}`)
export const syncInstance = (id) => service.post(`/v1/instances/${id}/sync`)
export const dispatchNode = (nodeId, data) => service.post(`/v1/nodes/${nodeId}/dispatch`, data || {})

export default service
