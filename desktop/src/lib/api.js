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

  let data
  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    data = await res.json()
  } else {
    const text = await res.text()
    try {
      data = JSON.parse(text)
    } catch {
      data = { error: text || 'Request failed' }
    }
  }

  if (!res.ok) throw new Error(data.error || 'Request failed')
  return data
}
