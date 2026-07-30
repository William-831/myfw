import { defineStore } from 'pinia'
import { ref } from 'vue'

// 保护期确认面板的跨组件开关:Nodes 页"待确认"标签点击 -> open() 唤起 Layout 中的面板
export const useGuardStore = defineStore('confirmGuard', () => {
  const drawerOpen = ref(false)
  const open = () => { drawerOpen.value = true }
  const close = () => { drawerOpen.value = false }
  return { drawerOpen, open, close }
})
