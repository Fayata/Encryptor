import React, { useState } from 'react'
import { Globe } from 'lucide-react'
import { useTranslation } from '../lib/i18n'

export default function SettingsView({ user, onLogout }) {
  const { language, setLanguage, t } = useTranslation()
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
        <div className="panel-head">{t('settings.appearance')}</div>
        <div className="panel-body">
          {/* Language Selection */}
          <div className="field" style={{ marginBottom: '20px' }}>
            <label className="field-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Globe size={14} style={{ color: 'var(--accent)' }} />
              <span>{t('settings.language')}</span>
            </label>
            <div className="segmented">
              <button
                type="button"
                className={language === 'id' ? 'active' : ''}
                onClick={() => setLanguage('id')}
              >
                🇮🇩 Bahasa Indonesia
              </button>
              <button
                type="button"
                className={language === 'en' ? 'active' : ''}
                onClick={() => setLanguage('en')}
              >
                🇬🇧 English
              </button>
            </div>
          </div>

          <div className="field">
            <label className="field-label">{t('settings.theme')}</label>
            <div className="segmented">
              <button className={theme === 'light' ? 'active' : ''} onClick={() => handleThemeChange('light')}>{t('settings.themeLight')}</button>
              <button className={theme === 'dark' ? 'active' : ''} onClick={() => handleThemeChange('dark')}>{t('settings.themeDark')}</button>
              <button className={theme === 'system' ? 'active' : ''} onClick={() => handleThemeChange('system')}>{t('settings.themeSystem')}</button>
            </div>
          </div>
          
          <div className="toggle-row">
            <div className="toggle-text">
              <strong>{t('settings.notifications')}</strong>
            </div>
            <div className="switch">
              <input type="checkbox" id="notif-toggle" checked={notifications} onChange={e => setNotifications(e.target.checked)} />
              <label htmlFor="notif-toggle"></label>
            </div>
          </div>
          
          <div className="toggle-row">
            <div className="toggle-text">
              <strong>{t('settings.startup')}</strong>
            </div>
            <div className="switch">
              <input type="checkbox" id="startup-toggle" checked={launchStartup} onChange={e => setLaunchStartup(e.target.checked)} />
              <label htmlFor="startup-toggle"></label>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">{t('settings.account')}</div>
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
          <button className="btn-secondary" style={{ width: '100%' }} onClick={onLogout}>{t('settings.signOut')}</button>
        </div>
      </div>
    </div>
  )
}