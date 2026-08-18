const API_BASE = 'http://localhost:8080'

let apiToken = localStorage.getItem('api_token') || ''

export function setToken(token) {
  apiToken = token
  localStorage.setItem('api_token', token)
}

export function getToken() {
  return apiToken
}

export function clearToken() {
  apiToken = ''
  localStorage.removeItem('api_token')
}

export async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Token': apiToken,
      ...options.headers,
    },
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || 'Request failed')
  return data
}
