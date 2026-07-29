<template>
  <div class="stat-card">
    <div class="stat-card__head">
      <span class="stat-card__label">{{ label }}</span>
      <el-icon class="stat-card__icon" :style="{ color: accent }">
        <component :is="icon" />
      </el-icon>
    </div>
    <p class="stat-card__value">{{ value }}</p>
    <div v-if="sub" class="stat-card__foot">
      <span class="stat-card__dot" :style="{ background: accent }"></span>
      <span>{{ sub }}</span>
    </div>
  </div>
</template>

<script setup>
/**
 * 极简商务数字卡:标签 + 大号等宽数字 + 副信息
 */
defineProps({
  icon: { type: [Object, Function], required: true },
  value: { type: [Number, String], default: 0 },
  label: { type: String, default: '' },
  accent: { type: String, default: 'var(--c-primary)' },
  sub: { type: String, default: '' }
})
</script>

<style scoped>
.stat-card {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 20px 22px;
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--radius);
  transition: border-color var(--transition), box-shadow var(--transition);
}

.stat-card:hover {
  border-color: var(--c-muted);
  box-shadow: var(--shadow-hover);
}

.stat-card__head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-card__label {
  font-size: 12px;
  letter-spacing: 0.04em;
  color: var(--c-text-3);
}

.stat-card__icon {
  font-size: 16px;
  opacity: 0.8;
}

.stat-card__value {
  margin: 0;
  font-size: 34px;
  font-weight: 600;
  line-height: 1;
  color: var(--c-text-1);
  font-variant-numeric: tabular-nums;
}

.stat-card__foot {
  display: flex;
  align-items: center;
  gap: 6px;
  padding-top: 10px;
  border-top: 1px solid var(--c-border-soft);
  font-size: 12px;
  color: var(--c-text-3);
}

.stat-card__dot {
  flex: 0 0 6px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
}
</style>
