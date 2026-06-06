import { useState, useEffect, useRef } from 'react'
import { uploadPolicy, reloadPolicies, fetchPolicyStats } from '../utils/api.js'

export default function PolicyManager() {
  const [stats,    setStats]   = useState(null)
  const [message,  setMessage] = useState('')
  const [loading,  setLoading] = useState(false)
  const fileRef = useRef()

  useEffect(() => { loadStats() }, [])

  async function loadStats() {
    try {
      const s = await fetchPolicyStats()
      setStats(s)
    } catch { setStats(null) }
  }

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    setMessage('')
    try {
      const r = await uploadPolicy(file)
      if (r.error) {
        setMessage(`❌ ${r.error}`)
      } else {
        setMessage(`✅ Uploaded "${r.filename}" — ${r.stats?.chunk_count} chunks now loaded`)
        setStats(r.stats)
      }
    } catch {
      setMessage('❌ Upload failed — is the backend running?')
    }
    setLoading(false)
    fileRef.current.value = ''
  }

  async function handleReload() {
    setLoading(true)
    setMessage('')
    try {
      const r = await reloadPolicies()
      setMessage(`✅ Policies reloaded — ${r.stats?.chunk_count} chunks, ${r.stats?.keyword_count} keywords`)
      setStats(r.stats)
    } catch {
      setMessage('❌ Reload failed — is the backend running?')
    }
    setLoading(false)
  }

  return (
    <div className="space-y-6">
      <h2 className="text-white font-semibold">Policy Manager</h2>
      <p className="text-gray-400 text-sm">
        Upload NovaTech policy documents (.txt prose or .json rules) to extend Blip's detection engine.
      </p>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Policy Chunks',  value: stats.chunk_count,    color: 'text-blue-400' },
            { label: 'Keywords',       value: stats.keyword_count,  color: 'text-yellow-400' },
            { label: 'Rules',          value: stats.rule_count,     color: 'text-purple-400' },
            { label: 'Block Threshold',value: `${Math.round(stats.block_threshold * 100)}%`, color: 'text-red-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-gray-400 text-xs mb-1">{s.label}</div>
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Model info */}
      {stats && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-sm">
          <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">Embedding Model</p>
          <p className="text-blue-400 font-mono">{stats.model}</p>
          <p className="text-gray-500 text-xs mt-1">
            Local CPU inference · No API · Air-gap compatible
          </p>
        </div>
      )}

      {/* Upload */}
      <div className="bg-gray-900 border border-gray-700 border-dashed rounded-xl p-6 text-center">
        <p className="text-gray-400 text-sm mb-3">
          Drop a <span className="text-blue-400">.txt</span> or{' '}
          <span className="text-blue-400">.json</span> policy file
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".txt,.json"
          onChange={handleUpload}
          className="hidden"
          id="policy-upload"
        />
        <label
          htmlFor="policy-upload"
          className="inline-block px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg cursor-pointer transition-colors"
        >
          {loading ? 'Uploading…' : 'Choose File'}
        </label>
      </div>

      {/* Reload */}
      <button
        onClick={handleReload}
        disabled={loading}
        className="px-5 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white text-sm font-semibold rounded-lg transition-colors"
      >
        {loading ? 'Reloading…' : '🔄 Reload All Policies'}
      </button>

      {message && (
        <p className="text-sm text-gray-300 bg-gray-800 rounded-lg p-3">{message}</p>
      )}

      {/* Threshold info */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-2 text-xs">
        <p className="text-gray-400 font-semibold mb-2">Decision Thresholds</p>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
          <span className="text-gray-300">Score ≥ 0.78 → <span className="text-red-400 font-bold">BLOCK</span></span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
          <span className="text-gray-300">Score 0.52–0.77 → <span className="text-amber-400 font-bold">SANITIZE</span></span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
          <span className="text-gray-300">Score &lt; 0.52 → <span className="text-green-400 font-bold">ALLOW</span></span>
        </div>
        <p className="text-gray-600 pt-1">+0.18 bonus added when keywords match any rule.</p>
      </div>
    </div>
  )
}
