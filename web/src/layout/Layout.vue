<template>
  <el-container class="layout-container">
    <el-aside width="220px" class="aside">
      <div class="logo">
        <span class="logo-text">MyFW</span>
        <span class="logo-sub">防火墙管理平台</span>
      </div>
      <el-menu :default-active="activeMenu" class="sidebar-menu" router>
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon>
          <span>概览</span>
        </el-menu-item>
        <el-menu-item index="/nodes">
          <el-icon><Connection /></el-icon>
          <span>节点管理</span>
        </el-menu-item>
        <el-menu-item index="/templates">
          <el-icon><Files /></el-icon>
          <span>策略模板库</span>
        </el-menu-item>
        <el-menu-item index="/node-policies">
          <el-icon><Monitor /></el-icon>
          <span>节点策略</span>
        </el-menu-item>
        <el-menu-item index="/address-groups">
          <el-icon><Coin /></el-icon>
          <span>地址组</span>
        </el-menu-item>
        <el-menu-item index="/custom-chains">
          <el-icon><Share /></el-icon>
          <span>自定义链</span>
        </el-menu-item>
        <el-menu-item index="/approve">
          <el-icon><CircleCheck /></el-icon>
          <span>审批中心</span>
        </el-menu-item>
        <el-menu-item index="/audit">
          <el-icon><Document /></el-icon>
          <span>审计日志</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container class="main-container">
      <el-header class="header">
        <span class="page-title">{{ pageTitle }}</span>
        <div class="header-right">
          <ConfirmGuard />
          <el-dropdown @command="handleCommand">
          <span class="user-info">
            <el-icon><User /></el-icon>
            <span>{{ username }}</span>
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">
                <el-icon><Key /></el-icon>修改密码
              </el-dropdown-item>
              <el-dropdown-item command="logout" divided>
                <el-icon><SwitchButton /></el-icon>退出登录
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        </div>
      </el-header>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>

    <!-- 修改密码对话框 -->
    <el-dialog v-model="pwDialogVisible" title="修改密码" width="420px" :close-on-click-modal="false">
      <el-form :model="pwForm" :rules="pwRules" ref="pwFormRef" label-width="80px">
        <el-form-item label="旧密码" prop="old">
          <el-input v-model="pwForm.old" type="password" show-password placeholder="请输入当前密码" />
        </el-form-item>
        <el-form-item label="新密码" prop="new">
          <el-input v-model="pwForm.new" type="password" show-password placeholder="至少 6 位" />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirm">
          <el-input v-model="pwForm.confirm" type="password" show-password placeholder="再次输入新密码" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="submitChangePassword" :loading="pwLoading">确认</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Odometer,
  Connection,
  Lock,
  CircleCheck,
  Document,
  Coin,
  Share,
  User,
  ArrowDown,
  Key,
  SwitchButton,
  Files,
  Monitor,
  Setting
} from '@element-plus/icons-vue'
import { changePassword } from '@/api'
import ConfirmGuard from '@/components/ConfirmGuard.vue'

const route = useRoute()
const router = useRouter()

const activeMenu = computed(() => route.path)

const pageTitles = {
  '/dashboard': '系统概览',
  '/nodes': '节点管理',
  '/policies': '策略管理',
  '/address-groups': '地址组管理',
  '/custom-chains': '自定义链',
  '/approve': '审批中心',
  '/audit': '审计日志',
  '/settings': '系统设置'
}

const pageTitle = computed(() => pageTitles[route.path] || 'MyFW')
const username = computed(() => localStorage.getItem('username') || '管理员')

// 修改密码
const pwDialogVisible = ref(false)
const pwLoading = ref(false)
const pwFormRef = ref(null)
const pwForm = reactive({ old: '', new: '', confirm: '' })
const pwRules = {
  old: [{ required: true, message: '请输入旧密码', trigger: 'blur' }],
  new: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 6, message: '新密码至少 6 位', trigger: 'blur' }
  ],
  confirm: [
    { required: true, message: '请确认新密码', trigger: 'blur' },
    {
      validator: (rule, value, cb) => (value === pwForm.new ? cb() : cb(new Error('两次输入的密码不一致'))),
      trigger: 'blur'
    }
  ]
}

const submitChangePassword = async () => {
  if (!pwFormRef.value) return
  await pwFormRef.value.validate()
  pwLoading.value = true
  try {
    await changePassword({ old_password: pwForm.old, new_password: pwForm.new })
    ElMessage.success('密码修改成功，请重新登录')
    pwDialogVisible.value = false
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    router.push('/login')
  } catch (err) {
    ElMessage.error(err?.response?.data?.error || '修改失败')
  } finally {
    pwLoading.value = false
  }
}

const handleCommand = (command) => {
  if (command === 'logout') {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    router.push('/login')
  } else if (command === 'password') {
    pwForm.old = ''
    pwForm.new = ''
    pwForm.confirm = ''
    pwDialogVisible.value = true
  }
}
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.aside {
  background: var(--c-sidebar);
  overflow: hidden;
}

.logo {
  display: flex;
  flex-direction: column;
  justify-content: center;
  height: 60px;
  padding: 0 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.logo-text {
  font-size: 18px;
  font-weight: 700;
  color: #fff;
  letter-spacing: 0.02em;
}

.logo-sub {
  margin-top: 2px;
  font-size: 11px;
  color: #64748b;
}

.sidebar-menu {
  border-right: none;
  background: transparent;
}

/* 菜单项:商务克制,选中态 indigo 左指示条 */
.sidebar-menu :deep(.el-menu-item) {
  height: 46px;
  line-height: 46px;
  margin: 4px 10px;
  padding-left: 14px !important;
  border-radius: 8px;
  color: #94a3b8;
  transition: background var(--transition), color var(--transition);
}

.sidebar-menu :deep(.el-menu-item:hover) {
  background: rgba(255, 255, 255, 0.04);
  color: #e2e8f0;
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  position: relative;
  background: rgba(79, 70, 229, 0.16);
  color: #fff;
}

.sidebar-menu :deep(.el-menu-item.is-active)::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 18px;
  border-radius: 0 3px 3px 0;
  background: var(--c-primary);
}

.main-container {
  flex-direction: column;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  background: var(--c-surface);
  border-bottom: 1px solid var(--c-border);
}

.page-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--c-text-1);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  color: var(--c-text-2);
  transition: color var(--transition);
}

.user-info:hover {
  color: var(--c-text-1);
}

.main-content {
  padding: 20px;
  background-color: var(--c-bg);
}
</style>
