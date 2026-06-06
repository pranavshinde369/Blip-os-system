export default function RiskScore({ score }) {
  const pct  = Math.round(score * 100)
  const r    = 18
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ

  const color =
    pct >= 78 ? '#ef4444' :
    pct >= 52 ? '#f59e0b' :
                '#22c55e'

  return (
    <div className="relative flex items-center justify-center w-12 h-12 shrink-0">
      <svg width="48" height="48" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r={r} fill="none" stroke="#1f2937" strokeWidth="4" />
        <circle
          cx="24" cy="24" r={r}
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 24 24)"
        />
      </svg>
      <span
        className="absolute text-xs font-bold"
        style={{ color }}
      >
        {pct}
      </span>
    </div>
  )
}
