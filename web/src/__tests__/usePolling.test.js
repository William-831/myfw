import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, ref, nextTick } from 'vue'
import { mount } from '@vue/test-utils'
import { usePolling } from '../composables/usePolling'

// 挂载一个用 usePolling 的组件,驱动 onMounted/onUnmounted 生命周期
const MountHost = (fn, interval, opts = {}) =>
  defineComponent({
    setup() {
      const { start, stop } = usePolling(fn, interval, opts)
      return { start, stop }
    },
    render: () => h('div'),
  })

describe('usePolling 轮询 composable', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('挂载后自动启动轮询,按间隔周期调用 fn', async () => {
    const fn = vi.fn()
    const wrapper = mount(MountHost(fn, 5000))
    expect(fn).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(10000)
    expect(fn).toHaveBeenCalledTimes(3)
    wrapper.unmount()
  })

  it('卸载后自动停止轮询,不再调用 fn', async () => {
    const fn = vi.fn()
    const wrapper = mount(MountHost(fn, 5000))
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1)
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(20000)
    expect(fn).toHaveBeenCalledTimes(1) // 卸载后不再累积
  })

  it('防重入:fn 未完成时跳过本次,完成后再按间隔恢复', async () => {
    let resolveFn
    const fn = vi.fn(() => new Promise((r) => { resolveFn = r }))
    const wrapper = mount(MountHost(fn, 5000))
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1)
    // 第一轮未 resolve,推进 15s(应跳过 3 次)
    await vi.advanceTimersByTimeAsync(15000)
    expect(fn).toHaveBeenCalledTimes(1)
    // resolve 后,下一周期恢复
    resolveFn()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('expose 的 stop 可手动停止', async () => {
    const fn = vi.fn()
    const wrapper = mount(MountHost(fn, 5000))
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1)
    wrapper.vm.stop()
    await vi.advanceTimersByTimeAsync(20000)
    expect(fn).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('fn 抛错不影响下一轮轮询(异常隔离)', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(undefined)
    const wrapper = mount(MountHost(fn, 5000))
    await vi.advanceTimersByTimeAsync(5000)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(2) // 异常后下一轮照常
    wrapper.unmount()
  })

  it('条件轮询:enabled=false 不轮询,变 true 启动,变 false 停止', async () => {
    const enabledRef = ref(false)
    const fn = vi.fn()
    const wrapper = mount(defineComponent({
      setup() {
        usePolling(fn, 5000, () => enabledRef.value)
        return {}
      },
      render: () => h('div'),
    }))
    await vi.advanceTimersByTimeAsync(10000)
    expect(fn).not.toHaveBeenCalled() // 条件不满足,空转 0 请求
    enabledRef.value = true
    await nextTick()
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1) // 条件满足后按间隔轮询
    enabledRef.value = false
    await nextTick()
    await vi.advanceTimersByTimeAsync(10000)
    expect(fn).toHaveBeenCalledTimes(1) // 条件不再满足,停止轮询
    wrapper.unmount()
  })
})
