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
  background: #f5f5f7;
  background-image:
    radial-gradient(ellipse 60% 40% at 20% 0%, rgba(0, 113, 227, 0.08), transparent 70%),
    radial-gradient(ellipse 50% 40% at 80% 100%, rgba(94, 92, 230, 0.06), transparent 70%);
}
.login-box {
  background: rgba(255, 255, 255, 0.72);
  backdrop-filter: blur(40px) saturate(180%);
  -webkit-backdrop-filter: blur(40px) saturate(180%);
  border: 1px solid rgba(0, 0, 0, 0.06);
  border-radius: 24px;
  padding: 48px;
  box-shadow: 0 8px 40px rgba(0, 0, 0, 0.08);
  width: 400px;
}
.logo-section { text-align: center; margin-bottom: 32px; }
.logo-icon { font-size: 48px; }
.logo-text { font-size: 32px; font-weight: 700; color: #1d1d1f; margin-left: 8px; letter-spacing: -0.02em; }
.logo-subtitle { font-size: 14px; color: #6e6e73; margin-top: 8px; }
.login-form { margin-bottom: 16px; }
.login-btn { width: 100%; height: 48px; font-size: 16px; border-radius: 12px; }
.hint-text { text-align: center; font-size: 12px; color: #aeaeb2; margin: 0; }
</style>