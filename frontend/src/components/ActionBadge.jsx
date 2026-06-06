const STYLES = {
  block:    'bg-red-500/20 text-red-400 border border-red-500/30',
  sanitize: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
  allow:    'bg-green-500/20 text-green-400 border border-green-500/30',
}

export default function ActionBadge({ action }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide ${STYLES[action] || STYLES.allow}`}>
      {action}
    </span>
  )
}
