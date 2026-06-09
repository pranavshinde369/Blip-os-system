import { useState, useEffect, useCallback } from 'react'
import { useBlipSocket }  from '../hooks/useBlipSocket.js'
import { fetchStats, fetchEvents } from '../utils/api.js'
import StatCard      from '../components/StatCard.jsx'
import EventRow      from '../components/EventRow.jsx'
import PayloadTester from '../components/PayloadTester.jsx'
import PolicyManager from '../components/PolicyManager.jsx'

const TABS = ['Live Feed', 'Payload Tester', 'Policy Manager']

export default function Dashboard() {
  const [tab,    setTab]    = useState('Live Feed')
  const [events, setEvents] = useState([])
  const [stats,  setStats]  = useState(null)

  // Load initial data
  useEffect(() => {
    fetchStats().then(setStats).catch(() => {})
    fetchEvents(50).then(es => setEvents(es.reverse())).catch(() => {})
  }, [])

  // Refresh stats every 5s
  useEffect(() => {
    const id = setInterval(() => {
      fetchStats().then(setStats).catch(() => {})
    }, 5000)
    return () => clearInterval(id)
  }, [])

  // Real-time events from WebSocket
  const onEvent = useCallback((event) => {
    setEvents(prev => [event, ...prev].slice(0, 200))
    setStats(prev => {
      if (!prev) return prev
      const next = { ...prev, total: prev.total + 1 }
      if (event.action === 'block')    next.blocked   = (prev.blocked   || 0) + 1
      if (event.action === 'sanitize') next.sanitized = (prev.sanitized || 0) + 1
      if (event.action === 'allow')    next.allowed   = (prev.allowed   || 0) + 1
      return next
    })
  }, [])

  const connected = useBlipSocket(onEvent)

  // Traffic breakdown bar
  const total = stats ? (stats.total || 1) : 1
  const blockPct    = Math.round(((stats?.blocked   || 0) / total) * 100)
  const sanitizePct = Math.round(((stats?.sanitized || 0) / total) * 100)
  const allowPct    = 100 - blockPct - sanitizePct

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🛡️</span>
          <div>
            <h1 className="text-white font-bold text-lg leading-none">Blip</h1>
            <p className="text-gray-500 text-xs">Policy-Native GenAI Firewall · NovaTech Solutions</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs text-gray-400">{connected ? 'Live' : 'Reconnecting…'}</span>
        </div>
      </header>

      <div className="px-6 py-6 space-y-6 max-w-7xl mx-auto">
        {/* Stats bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Events"   value={stats?.total     ?? '—'} color="text-white" />
          <StatCard label="Blocked"        value={stats?.blocked   ?? '—'} color="text-red-400" />
          <StatCard label="Sanitized"      value={stats?.sanitized ?? '—'} color="text-amber-400" />
          <StatCard label="Avg Risk Score" value={stats ? `${Math.round((stats.avg_score || 0) * 100)}%` : '—'} color="text-blue-400" />
        </div>

        {/* Traffic breakdown bar */}
        {stats?.total > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-gray-400 text-xs uppercase tracking-wider mb-3">Traffic Breakdown</p>
            <div className="flex rounded-full overflow-hidden h-4">
              {blockPct > 0    && <div className="bg-red-500 transition-all"    style={{ width: `${blockPct}%` }} title={`Blocked ${blockPct}%`} />}
              {sanitizePct > 0 && <div className="bg-amber-500 transition-all"  style={{ width: `${sanitizePct}%` }} title={`Sanitized ${sanitizePct}%`} />}
              {allowPct > 0    && <div className="bg-green-600 transition-all"  style={{ width: `${allowPct}%` }} title={`Allowed ${allowPct}%`} />}
            </div>
            <div className="flex gap-4 mt-2 text-xs text-gray-400">
              <span><span className="text-red-400">■</span> Blocked {blockPct}%</span>
              <span><span className="text-amber-400">■</span> Sanitized {sanitizePct}%</span>
              <span><span className="text-green-400">■</span> Allowed {allowPct}%</span>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-gray-800">
          {TABS.map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                tab === t
                  ? 'text-blue-400 border-blue-400'
                  : 'text-gray-500 border-transparent hover:text-gray-300'
              }`}
            >
              {t}
              {t === 'Live Feed' && events.length > 0 && (
                <span className="ml-2 px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs rounded">
                  {events.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === 'Live Feed' && (
          <div className="space-y-2">
            {events.length === 0 ? (
              <div className="text-center py-20 text-gray-600">
                <p className="text-4xl mb-3">📡</p>
                <p>Waiting for events…</p>
                <p className="text-xs mt-2">Run <code className="bg-gray-800 px-1 rounded">python demo_sim.py</code> to populate</p>
              </div>
            ) : (
              events.map(e => <EventRow key={e.id ?? e.timestamp} event={e} />)
            )}
          </div>
        )}

        {tab === 'Payload Tester' && <PayloadTester />}
        {tab === 'Policy Manager' && <PolicyManager />}
      </div>
    </div>
  )
}
