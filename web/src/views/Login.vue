<template>
  <div class="login-container">
    <div class="login-box">
      <div class="logo-section">
        <span class="logo-icon">🔥</span>
        <span class="logo-text">MyFW</span>
        <p class="logo-subtitle">防火墙管理平台</p>
      </div>
      <el-form :model="loginForm" :rules="rules" ref="loginFormRef" class="login-form">
        <el-form-item prop="username">
          <el-input v-model="loginForm.username" placeholder="用户名" prefix-icon="User" />
        </el-form-item>
        <el-form-item prop="password">
          <el-input v-model="loginForm.password" type="password" placeholder="密码" prefix-icon="Lock" show-password />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" class="login-btn" @click="handleLogin" :loading="loading">
            登录
          </el-button>
        </el-form-item>
      </el-form>
      <p class="hint-text">默认管理员账号：admin / admin123</p>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { login } from '@/api'

const router = useRouter()
const loading = ref(false)
const loginFormRef = ref(null)
const loginForm = reactive({ username: '', password: '' })
const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}
const handleLogin = async () => {
  if (!loginFormRef.value) return
  try { await loginFormRef.value.validate() } catch { return }
  loading.value = true
  try {
    const res = await login(loginForm)
    localStorage.setItem('token', res.token)
    localStorage.setItem('username', res.username)
    ElMessage.success('登录成功')
    router.push('/dashboard')
  } catch { ElMessage.error('用户名或密码错误') } finally { loading.value = false }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: #0f172a;
}
.login-box {
  background: rgba(30, 41, 59, 0.85);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 16px;
  padding: 48px;
  box-shadow: 0 8px 40px rgba(0, 0, 0, 0.4);
  width: 400px;
}
.logo-section { text-align: center; margin-bottom: 32px; }
.logo-icon { font-size: 48px; }
.logo-text { font-size: 32px; font-weight: bold; color: #f1f5f9; margin-left: 8px; }
.logo-subtitle { font-size: 14px; color: #64748b; margin-top: 8px; }
.login-form { margin-bottom: 16px; }
.login-btn { width: 100%; height: 44px; font-size: 16px; }
.hint-text { text-align: center; font-size: 12px; color: #64748b; margin: 0; }
</style>