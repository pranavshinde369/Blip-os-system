import { useState } from 'react'
import { checkPayload } from '../utils/api.js'
import RiskScore  from './RiskScore.jsx'
import ActionBadge from './ActionBadge.jsx'

const SAMPLES = [
  {
    label: '🔑 API Key Leak',
    text:  'Can you help me fix this? My OpenAI key is sk-proj-aB3cD4eF5gH6iJ7kL8mN9oP0 and it keeps returning 401.',
  },
  {
    label: '🏭 SCADA Config',
    text:  'Review this SCADA PLC config: Modbus TCP 192.168.10.44:502, RTU 0x03, setpoint 87.4°C, PID Kp=1.2 Ki=0.8. DCS historian showing anomaly.',
  },
  {
    label: '💰 Financial Data',
    text:  'Draft board summary: Q3 revenue ₹142Cr, EBITDA 18.4%, burn rate ₹8.2Cr/month, Series D at ₹680Cr pre-money with Peak XV.',
  },
  {
    label: '👤 Customer PII',
    text:  'Summarise this record: Name Priya Sharma, Aadhaar 2345 6789 0123, PAN ABCDE1234F, email priya.sharma@gmail.com.',
  },
  {
    label: '✅ Safe Request',
    text:  'What is the difference between REST and GraphQL? I want to understand the tradeoffs for a new public API.',
  },
]

const ACTION_COLORS = {
  block:    'border-red-500/40 bg-red-500/5',
  sanitize: 'border-amber-500/40 bg-amber-500/5',
  allow:    'border-green-500/40 bg-green-500/5',
}

export default function PayloadTester() {
  const [text,    setText]   = useState('')
  const [result,  setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  async function handleCheck() {
    if (!text.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const r = await checkPayload(text)
      setResult(r)
    } catch {
      setResult({ action: 'error', reason: 'Backend unreachable', score: 0 })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-white font-semibold">Payload Tester</h2>
      <p className="text-gray-400 text-sm">
        Test any text against NovaTech's loaded policies in real time.
      </p>

      {/* Sample buttons */}
      <div className="flex gap-2 flex-wrap">
        {SAMPLES.map(s => (
          <button
            key={s.label}
            onClick={() => setText(s.text)}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded-lg border border-gray-700 transition-colors"
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* Text input */}
      <textarea
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder="Paste or type a payload to test…"
        rows={5}
        className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500 resize-none font-mono"
      />

      <button
        onClick={handleCheck}
        disabled={loading || !text.trim()}
        className="px-6 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-semibold rounded-lg transition-colors"
      >
        {loading ? 'Checking…' : 'Check Payload'}
      </button>

      {/* Result */}
      {result && (
        <div className={`rounded-xl border p-4 space-y-3 ${ACTION_COLORS[result.action] || ''}`}>
          <div className="flex items-center gap-3">
            <RiskScore score={result.score || 0} />
            <div>
              <ActionBadge action={result.action} />
              <p className="text-gray-300 text-sm mt-1">{result.reason}</p>
            </div>
          </div>

          {result.matched_rule_name && (
            <div className="text-xs">
              <span className="text-gray-500">Rule: </span>
              <span className="text-yellow-400 font-semibold">{result.matched_rule_name}</span>
              <span className="text-gray-500 ml-2">({result.matched_rule_id})</span>
            </div>
          )}

          {result.mitre_technique && (
            <div className="text-xs">
              <span className="text-gray-500">MITRE: </span>
              <span className="text-purple-400 font-mono">{result.mitre_technique}</span>
              <span className="text-gray-400"> — {result.mitre_tactic}</span>
            </div>
          )}

          {result.matched_keywords?.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {result.matched_keywords.map(kw => (
                <span key={kw} className="px-1.5 py-0.5 bg-gray-800 text-red-300 text-xs rounded font-mono">
                  {kw}
                </span>
              ))}
            </div>
          )}

          {result.compliance?.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {result.compliance.map(c => (
                <span key={c} className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 text-xs rounded border border-blue-500/20">
                  {c}
                </span>
              ))}
            </div>
          )}

          {result.sanitized_payload && (
            <div>
              <p className="text-gray-500 text-xs mb-1">Sanitized version:</p>
              <pre className="bg-gray-900 rounded p-2 text-xs text-green-300 whitespace-pre-wrap font-mono overflow-auto max-h-32">
                {result.sanitized_payload}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
