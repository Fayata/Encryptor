import React, { useState } from 'react'
import { Shield } from 'lucide-react'
import { api, setToken } from '../lib/api'

export default function LoginView({ onLogin }) {
  const [isRegister, setIsRegister] = useState(false)
  const [serverUrl, setServerUrl] = useState('http://localhost:8080')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    
    try {
      const endpoint = isRegister ? '/api/auth/register' : '/api/auth/login'
      const payload = isRegister 
        ? { username, email, password }
        : { username_or_email: username, password }

      const data = await api(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload)
      })

      // Generate Master Key locally using backend KDF helper
      const kdfData = await api('/api/local/kdf', {
        method: 'POST',
        body: JSON.stringify({ password, salt: email || username }) // use email/username as salt
      })

      if (data.api_token) {
        setToken(data.api_token)
        onLogin(data.user, data.api_token, kdfData.master_key)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-wrapper">
      <div className="auth-card">
        <div className="auth-header">
          <Shield size={48} className="auth-icon" />
          <h2>{isRegister ? 'Create Account' : 'Sign in to Faycryptor'}</h2>
        </div>
        
        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>{isRegister ? 'Username' : 'Username or Email'}</label>
            <input 
              type="text" 
              className="form-control" 
              value={username} 
              onChange={e => setUsername(e.target.value)} 
              required 
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label>Email</label>
              <input 
                type="email" 
                className="form-control" 
                value={email} 
                onChange={e => setEmail(e.target.value)} 
                required 
              />
            </div>
          )}
          
          <div className="form-group">
            <label>Password</label>
            <input 
              type="password" 
              className="form-control" 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
              required 
            />
          </div>
          
          <button type="submit" className="btn-primary btn-full" disabled={loading}>
            {loading ? 'Processing...' : (isRegister ? 'Register' : 'Sign in')}
          </button>
        </form>

        <div className="auth-footer">
          {isRegister ? (
            <span>Already have an account? <button className="link-btn" onClick={() => setIsRegister(false)}>Sign in</button></span>
          ) : (
            <span>Don't have an account? <button className="link-btn" onClick={() => setIsRegister(true)}>Register</button></span>
          )}
        </div>
      </div>
    </div>
  )
}
