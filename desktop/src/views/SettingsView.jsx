import React, { useState } from 'react'

export default function SettingsView({ user, onLogout }) {
  const [theme, setTheme] = useState('system')
  const [notifications, setNotifications] = useState(true)
  const [launchStartup, setLaunchStartup] = useState(false)

  const handleThemeChange = (newTheme) => {
    setTheme(newTheme)
    document.documentElement.setAttribute('data-theme', newTheme)
  }

  return (
    <div className="view-narrow">
      <div className="panel">
        <div className="panel-head">Appearance</div>
        <div className="panel-body">
          <div className="field">
            <label className="field-label">Theme</label>
            <div className="segmented">
              <button className={theme === 'light' ? 'active' : ''} onClick={() => handleThemeChange('light')}>Light</button>
              <button className={theme === 'dark' ? 'active' : ''} onClick={() => handleThemeChange('dark')}>Dark</button>
              <button className={theme === 'system' ? 'active' : ''} onClick={() => handleThemeChange('system')}>System</button>
            </div>
          </div>
          
          <div className="toggle-row">
            <div className="toggle-text">
              <strong>Desktop notifications</strong>
            </div>
            <div className="switch">
              <input type="checkbox" id="notif-toggle" checked={notifications} onChange={e => setNotifications(e.target.checked)} />
              <label htmlFor="notif-toggle"></label>
            </div>
          </div>
          
          <div className="toggle-row">
            <div className="toggle-text">
              <strong>Launch on startup</strong>
            </div>
            <div className="switch">
              <input type="checkbox" id="startup-toggle" checked={launchStartup} onChange={e => setLaunchStartup(e.target.checked)} />
              <label htmlFor="startup-toggle"></label>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">Account</div>
        <div className="panel-body">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
            <div className="avatar" style={{ width: '48px', height: '48px', fontSize: '20px' }}>
              {user?.username ? user.username.charAt(0).toUpperCase() : 'U'}
            </div>
            <div>
              <strong style={{ fontSize: '16px' }}>{user?.username || 'User'}</strong>
              <div style={{ color: 'var(--text-muted)' }}>{user?.email || 'user@example.com'}</div>
            </div>
          </div>
          <button className="btn-secondary" style={{ width: '100%' }} onClick={onLogout}>Sign out</button>
        </div>
      </div>
    </div>
  )
}