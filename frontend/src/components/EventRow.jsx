import RiskScore  from './RiskScore.jsx'
import ActionBadge from './ActionBadge.jsx'
import { useState } from 'react'

const SEV_COLOR = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  MEDIUM:   'text-amber-400 bg-amber-500/10 border-amber-500/20',
  LOW:      'text-green-400 bg-green-500/10 border-green-500/20',
}

function fmt(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-IN', { hour12: false })
}

export default function EventRow({ event }) {
  const [open, setOpen] = useState(false)

  const sevClass = SEV_COLOR[event.severity] || SEV_COLOR.LOW

  return (
    <div
      className="animate-slide-in border border-gray-800 rounded-lg bg-gray-900/60 overflow-hidden cursor-pointer hover:border-gray-600 transition-colors"
      onClick={() => setOpen(o => !o)}
    >
      {/* Summary row */}
      <div className="flex items-center gap-3 p-3">
        <RiskScore score={event.score} />

        <div className="flex flex-col gap-1 min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <ActionBadge action={event.action} />
            {event.severity && (
              <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${sevClass}`}>
                {event.severity}
              </span>
            )}
            {event.mitre_technique && (
              <span className="px-2 py-0.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                {event.mitre_technique}
              </span>
            )}
            <span className="text-gray-400 text-xs ml-auto">{fmt(event.timestamp)}</span>
          </div>

          <div className="flex items-center gap-2 text-xs text-gray-400 flex-wrap">
            <span className="text-blue-400 font-medium">{event.destination}</span>
            <span>·</span>
            <span className="text-gray-500">{event.source}</span>
            {event.matched_rule_name && (
              <>
                <span>·</span>
                <span className="text-yellow-500">{event.matched_rule_name}</span>
              </>
            )}
          </div>

          <p className="text-gray-300 text-xs truncate">{event.payload_preview}</p>

          {/* Keywords */}
          {event.matched_keywords?.length > 0 && (
            <div className="flex gap-1 flex-wrap mt-1">
              {event.matched_keywords.slice(0, 6).map(kw => (
                <span key={kw} className="px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs rounded font-mono">
                  {kw}
                </span>
              ))}
            </div>
          )}
        </div>

        <span className="text-gray-600 text-xs shrink-0">{open ? '▲' : '▼'}</span>
      </div>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-gray-800 p-3 space-y-2 text-xs">
          <div>
            <span className="text-gray-500">Reason: </span>
            <span className="text-gray-300">{event.reason}</span>
          </div>
          {event.mitre_tactic && (
            <div>
              <span className="text-gray-500">MITRE Tactic: </span>
              <span className="text-purple-300">{event.mitre_tactic}</span>
            </div>
          )}
          {event.compliance?.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              <span className="text-gray-500 mr-1">Compliance:</span>
              {event.compliance.map(c => (
                <span key={c} className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">
                  {c}
                </span>
              ))}
            </div>
          )}
          {event.policy_chunk_source && (
            <div>
              <span className="text-gray-500">Policy source: </span>
              <span className="text-gray-300 font-mono">{event.policy_chunk_source}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
