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

export const login = (data) => service.post('/auth/login', data)

export const getNodes = (params) => service.get('/nodes', { params })
export const getNode = (id) => service.get(`/nodes/${id}`)
export const updateNode = (id, data) => service.put(`/nodes/${id}`, data)
export const deleteNode = (id) => service.delete(`/nodes/${id}`)

export const getPolicies = (params) => service.get('/policies', { params })
export const createPolicy = (data) => service.post('/policies', data)
export const getPolicy = (id) => service.get(`/policies/${id}`)
export const updatePolicy = (id, data) => service.put(`/policies/${id}`, data)
export const deletePolicy = (id) => service.delete(`/policies/${id}`)
export const applyPolicy = (id) => service.post(`/policies/${id}/apply`)

export const getApprovals = (params) => service.get('/approvals', { params })
export const approve = (id) => service.post(`/approvals/${id}/approve`)
export const reject = (id) => service.post(`/approvals/${id}/reject`)

export const getAudits = (params) => service.get('/audit/logs', { params })
export const exportAudits = (params) => service.get('/audit/export', { params, responseType: 'blob' })

export const getDashboardStats = () => service.get('/dashboard/stats')

export default service