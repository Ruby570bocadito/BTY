<template>
  <div class="space-y-6 animate-fadeIn">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white font-mono tracking-tight">DASHBOARD</h1>
        <p class="text-gray-600 text-sm mt-1">Real-time operational overview</p>
      </div>
      <div class="flex items-center gap-2 text-xs text-gray-600 font-mono">
        <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
        LIVE
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-4 gap-4">
      <div class="stat-card border-l-emerald-500">
        <div class="text-3xl font-bold font-mono text-emerald-400">{{ sessions.length }}</div>
        <div class="text-xs text-gray-500 uppercase tracking-widest mt-2">Active Sessions</div>
        <div class="mt-3 h-1 bg-gray-800 rounded-full overflow-hidden">
          <div class="h-full bg-emerald-500/50 rounded-full animate-pulse" style="width: 100%"></div>
        </div>
      </div>
      <div class="stat-card border-l-cyan-500">
        <div class="text-3xl font-bold font-mono text-cyan-400">{{ taskCount || '—' }}</div>
        <div class="text-xs text-gray-500 uppercase tracking-widest mt-2">Total Tasks</div>
        <div class="mt-3 h-1 bg-gray-800 rounded-full overflow-hidden">
          <div class="h-full bg-cyan-500/50 rounded-full" style="width: 70%"></div>
        </div>
      </div>
      <div class="stat-card border-l-amber-500">
        <div class="text-3xl font-bold font-mono text-amber-400">{{ listeners }}</div>
        <div class="text-xs text-gray-500 uppercase tracking-widest mt-2">Listeners</div>
        <div class="mt-3 flex gap-1">
          <span class="h-1 flex-1 bg-amber-500/50 rounded-full"></span>
          <span class="h-1 flex-1 bg-amber-500/30 rounded-full"></span>
          <span class="h-1 flex-1 bg-amber-500/20 rounded-full"></span>
        </div>
      </div>
      <div class="stat-card border-l-purple-500">
        <div class="text-3xl font-bold font-mono text-purple-400">{{ onlineMinutes }}m</div>
        <div class="text-xs text-gray-500 uppercase tracking-widest mt-2">Uptime</div>
        <div class="mt-3 h-1 bg-gray-800 rounded-full overflow-hidden">
          <div class="h-full bg-purple-500/50 rounded-full" :style="{ width: Math.min(onlineMinutes / 60 * 100, 100) + '%' }"></div>
        </div>
      </div>
    </div>

    <!-- Main content grid -->
    <div class="grid grid-cols-2 gap-4">
      <!-- OS Distribution -->
      <div class="panel">
        <div class="panel-header">
          <h2>OS DISTRIBUTION</h2>
          <span class="text-xs text-gray-600">{{ sessions.length }} hosts</span>
        </div>
        <div class="space-y-4 p-4">
          <div v-for="(count, os) in osStats" :key="os" class="group">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-sm text-gray-300 capitalize font-mono">{{ os || 'unknown' }}</span>
              <span class="text-xs text-gray-500 font-mono">{{ count }}</span>
            </div>
            <div class="w-full bg-gray-800/50 rounded-full h-2 overflow-hidden">
              <div class="h-full rounded-full transition-all duration-500"
                :class="osBarColor(os)"
                :style="{ width: (count / sessions.length * 100) + '%' }"></div>
            </div>
          </div>
          <div v-if="Object.keys(osStats).length === 0" class="text-center text-gray-700 py-6 font-mono text-sm">
            No sessions connected
          </div>
        </div>
      </div>

      <!-- Recent Sessions -->
      <div class="panel">
        <div class="panel-header">
          <h2>RECENT SESSIONS</h2>
          <span class="text-xs text-gray-600">{{ sessions.length }} active</span>
        </div>
        <div class="divide-y divide-gray-800/50 max-h-[300px] overflow-y-auto">
          <div v-for="s in sessions.slice(0, 8)" :key="s.ID"
            class="px-4 py-3 hover:bg-gray-800/20 transition-colors cursor-pointer group"
            @click="$router.push('/sessions')">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <span class="w-2 h-2 rounded-full flex-shrink-0"
                  :class="s.State === 'active' ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50' : 'bg-gray-700'"></span>
                <span class="text-sm text-gray-200 font-mono">{{ s.Hostname || 'unknown' }}</span>
              </div>
              <div class="flex items-center gap-3 text-xs text-gray-600 font-mono">
                <span class="capitalize">{{ s.OS || '?' }}</span>
                <span>{{ s.Arch || '?' }}</span>
              </div>
            </div>
            <div class="flex items-center gap-3 mt-1.5 ml-5 text-xs text-gray-600">
              <span>{{ s.Username || '?' }}</span>
              <span v-if="s.IsAdmin" class="text-amber-500 text-[10px] font-bold uppercase tracking-wider bg-amber-950/30 px-1.5 py-0.5 rounded">ADMIN</span>
            </div>
          </div>
          <div v-if="sessions.length === 0" class="py-12 text-center">
            <div class="text-gray-700 text-4xl mb-3">◈</div>
            <p class="text-gray-600 font-mono text-sm">Awaiting agent connections...</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Quick Command -->
    <div class="panel">
      <div class="panel-header">
        <h2>QUICK COMMAND</h2>
        <span class="text-xs text-gray-600">broadcast or target</span>
      </div>
      <div class="p-4">
        <div class="flex gap-3">
          <select v-model="targetAgent" class="bg-[#0a0e17] border border-gray-800 rounded-lg px-3 py-2.5 text-sm font-mono text-gray-300 outline-none focus:border-emerald-500/50 transition-all w-64">
            <option value="">ALL AGENTS (broadcast)</option>
            <option v-for="s in sessions" :key="s.ID" :value="s.ID">{{ s.Hostname }} ({{ s.Username }})</option>
          </select>
          <input v-model="quickCmd" @keyup.enter="runQuickCmd"
            class="flex-1 bg-[#0a0e17] border border-gray-800 focus:border-emerald-500/50 rounded-lg px-4 py-2.5 text-sm font-mono text-emerald-300 placeholder-gray-700 outline-none transition-all"
            placeholder="$ command..." />
          <button @click="runQuickCmd" class="bg-emerald-600 hover:bg-emerald-500 px-6 py-2.5 rounded-lg text-sm font-mono font-semibold transition-all duration-300 shadow-lg shadow-emerald-900/20">
            EXECUTE
          </button>
        </div>
        <pre v-if="cmdResult" class="mt-4 bg-[#0a0e17] rounded-lg p-4 text-xs font-mono text-gray-300 max-h-64 overflow-y-auto border border-gray-800/50 leading-relaxed">{{ cmdResult }}</pre>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      sessions: [], taskCount: null, listeners: 0, uptime: 0,
      onlineMinutes: 0, osStats: {}, quickCmd: '', targetAgent: '', cmdResult: '',
      timer: null
    }
  },
  mounted() {
    this.refresh()
    this.timer = setInterval(() => this.refresh(), 4000)
  },
  beforeUnmount() { clearInterval(this.timer) },
  methods: {
    auth() { return { Authorization: 'Basic ' + sessionStorage.getItem('bty_auth') } },
    async refresh() {
      try {
        const [sessRes, healthRes] = await Promise.all([
          fetch('/api/sessions', { headers: this.auth() }),
          fetch('/api/health', { headers: this.auth() })
        ])
        this.sessions = await sessRes.json() || []
        const h = await healthRes.json()
        this.listeners = h.listeners || 0
        this.uptime = h.uptime || 0
        this.onlineMinutes = Math.floor((Date.now()/1000 - this.uptime) / 60) || 0
        this.taskCount = h.total_tasks ?? h.task_count ?? null
        this.osStats = {}
        this.sessions.forEach(s => {
          const os = s.OS || 'unknown'
          this.osStats[os] = (this.osStats[os] || 0) + 1
        })
      } catch (e) {}
    },
    osBarColor(os) {
      const colors = { linux: 'bg-amber-500/70', windows: 'bg-blue-500/70', darwin: 'bg-gray-400/70' }
      return colors[os] || 'bg-emerald-500/70'
    },
    async runQuickCmd() {
      if (!this.quickCmd) return
      const url = this.targetAgent ? '/api/cmd' : '/api/broadcast'
      const body = this.targetAgent
        ? JSON.stringify({ agent_id: this.targetAgent, command: this.quickCmd, timeout: 15 })
        : JSON.stringify({ command: this.quickCmd })
      try {
        const r = await fetch(url, { method: 'POST', headers: { ...this.auth(), 'Content-Type': 'application/json' }, body })
        const j = await r.json()
        this.cmdResult = typeof j === 'string' ? j : JSON.stringify(j, null, 2)
      } catch (e) { this.cmdResult = 'Error: ' + e.message }
      this.quickCmd = ''
    }
  }
}
</script>

<style scoped>
.stat-card {
  @apply bg-[#0d1117] border border-gray-800/50 rounded-xl p-5 border-l-2;
  transition: all 0.3s ease;
}
.stat-card:hover {
  @apply border-gray-700/50;
  transform: translateY(-1px);
}
.panel {
  @apply bg-[#0d1117] border border-gray-800/50 rounded-xl overflow-hidden;
}
.panel-header {
  @apply flex items-center justify-between px-4 py-3 border-b border-gray-800/50;
}
.panel-header h2 {
  @apply text-xs font-semibold text-gray-400 uppercase tracking-widest font-mono;
}
.animate-fadeIn {
  animation: fadeIn 0.5s ease-out;
}
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
