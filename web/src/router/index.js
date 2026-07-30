import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue')
  },
  {
    path: '/',
    name: 'Layout',
    component: () => import('@/layout/Layout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue')
      },
      {
        path: 'nodes',
        name: 'Nodes',
        component: () => import('@/views/Nodes.vue')
      },
      {
        path: 'policies',
        redirect: '/templates'
      },
      {
        path: 'templates',
        name: 'Templates',
        component: () => import('@/views/TemplateLibrary.vue')
      },
      {
        path: 'node-policies',
        name: 'NodePolicies',
        component: () => import('@/views/NodePolicies.vue')
      },
      {
        path: 'address-groups',
        name: 'AddressGroups',
        component: () => import('@/views/AddressGroups.vue')
      },
      {
        path: 'custom-chains',
        name: 'CustomChains',
        component: () => import('@/views/CustomChains.vue')
      },
      {
        path: 'approve',
        name: 'Approve',
        component: () => import('@/views/Approve.vue')
      },
      {
        path: 'audit',
        name: 'Audit',
        component: () => import('@/views/Audit.vue')
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) {
    next('/login')
  } else {
    next()
  }
})

export default router