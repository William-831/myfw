<template>
  <el-container class="layout-container">
    <el-aside width="220px" class="aside">
      <div class="logo">
        <span class="logo-icon">🔥</span>
        <span class="logo-text">MyFW</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        class="sidebar-menu"
        background-color="#1f2937"
        text-color="#9ca3af"
        active-text-color="#fff"
        router
      >
        <el-menu-item index="/dashboard">
          <el-icon><Dashboard /></el-icon>
          <span>概览</span>
        </el-menu-item>
        <el-menu-item index="/nodes">
          <el-icon><Network /></el-icon>
          <span>节点管理</span>
        </el-menu-item>
        <el-menu-item index="/policies">
          <el-icon><Lock /></el-icon>
          <span>策略管理</span>
        </el-menu-item>
        <el-menu-item index="/approve">
          <el-icon><CheckCircle /></el-icon>
          <span>审批中心</span>
        </el-menu-item>
        <el-menu-item index="/audit">
          <el-icon><Document /></el-icon>
          <span>审计日志</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container class="main-container">
      <el-header class="header">
        <div class="header-left">
          <el-icon class="toggle-btn" @click="toggleCollapse"><Menu /></el-icon>
          <span class="page-title">{{ pageTitle }}</span>
        </div>
        <div class="header-right">
          <el-dropdown @command="handleCommand">
            <span class="user-info">
              <el-icon><User /></el-icon>
              <span>{{ username }}</span>
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  Dashboard,
  Network,
  Lock,
  CheckCircle,
  Document,
  Menu,
  User,
  ArrowDown
} from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const activeMenu = computed(() => route.path)

const pageTitles = {
  '/dashboard': '系统概览',
  '/nodes': '节点管理',
  '/policies': '策略管理',
  '/approve': '审批中心',
  '/audit': '审计日志'
}

const pageTitle = computed(() => pageTitles[route.path] || 'MyFW')
const username = computed(() => localStorage.getItem('username') || '管理员')

const handleCommand = (command) => {
  if (command === 'logout') {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    router.push('/login')
  }
}
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.aside {
  background-color: #1f2937;
  overflow: hidden;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 60px;
  padding: 0 20px;
  border-bottom: 1px solid #374151;
}

.logo-icon {
  font-size: 24px;
  margin-right: 8px;
}

.logo-text {
  font-size: 18px;
  font-weight: bold;
  color: #fff;
}

.sidebar-menu {
  border-right: none;
}

.main-container {
  flex-direction: column;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background-color: #fff;
  border-bottom: 1px solid #e5e7eb;
}

.header-left {
  display: flex;
  align-items: center;
}

.toggle-btn {
  font-size: 20px;
  margin-right: 16px;
  cursor: pointer;
  color: #6b7280;
}

.page-title {
  font-size: 18px;
  font-weight: 600;
  color: #1f2937;
}

.header-right {
  display: flex;
  align-items: center;
}

.user-info {
  display: flex;
  align-items: center;
  cursor: pointer;
  color: #374151;
}

.user-info span {
  margin-left: 4px;
}

.main-content {
  padding: 20px;
  background-color: #f3f4f6;
}
</style>