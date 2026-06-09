const BASE = '/api'

export async function fetchStats() {
  const r = await fetch(`${BASE}/stats`)
  return r.json()
}

export async function fetchEvents(limit = 100, action = null) {
  const params = new URLSearchParams({ limit })
  if (action) params.append('action', action)
  const r = await fetch(`${BASE}/events?${params}`)
  return r.json()
}

export async function checkPayload(payload) {
  const r = await fetch(`${BASE}/check`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ payload, source: 'dashboard', destination: 'tester' }),
  })
  return r.json()
}

export async function uploadPolicy(file) {
  const form = new FormData()
  form.append('file', file)
  const r = await fetch(`${BASE}/policies/upload`, { method: 'POST', body: form })
  return r.json()
}

export async function reloadPolicies() {
  const r = await fetch(`${BASE}/policies/reload`, { method: 'POST' })
  return r.json()
}

export async function fetchPolicyStats() {
  const r = await fetch(`${BASE}/policies/stats`)
  return r.json()
}
