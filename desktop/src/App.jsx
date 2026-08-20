import React, { useState, useEffect } from 'react'
import { Bell, HelpCircle } from 'lucide-react'
import { getToken, clearToken, api } from './lib/api'

import Titlebar from './components/Titlebar'
import Sidebar from './components/Sidebar'
import LoginView from './views/LoginView'
import HomeView from './views/HomeView'
import EncryptView from './views/EncryptView'
import DecryptView from './views/DecryptView'
import KeysView from './views/KeysView'
import SettingsView from './views/SettingsView'
import AboutView from './views/AboutView'
import PlaceholderView from './views/PlaceholderView'
import WorkspaceView from './views/WorkspaceView'
import { useTranslation } from './lib/i18n'

class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { hasError: false, error: null, info: null }; }
  static getDerivedStateFromError(error) { return { hasError: true, error }; }
  componentDidCatch(error, info) { this.setState({ info }); }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{padding: "24px", color: "white", background: "var(--danger)", height: "100%", borderRadius: "8px"}}>
          <h3>UI Component Crashed</h3>
          <p style={{marginBottom: "16px"}}>An error occurred while rendering this view.</p>
          <pre style={{background: "rgba(0,0,0,0.2)", padding: "16px", borderRadius: "4px", overflowX: "auto", fontSize: "12px"}}>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.info && this.state.info.componentStack}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const { t } = useTranslation()
  const [currentView, setCurrentView] = useState('home')
  const [user, setUser] = useState(null)
  const [masterKey, setMasterKey] = useState(null)
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [userOrgs, setUserOrgs] = useState([])
  const [activeOrg, setActiveOrg] = useState(null)

  const viewLabels = {
    home: t('nav.home'),
    encrypt: t('nav.encrypt'),
    decrypt: t('nav.file'),
    workspace: t('nav.workspace'),
    org: t('nav.workspace'),
    connections: t('nav.workspace'),
    keys: t('nav.keys'),
    settings: t('nav.settings'),
    about: t('nav.about')
  }

  useEffect(() => {
    // We cannot auto-login because the Master Key (derived from password) 
    // must be kept in memory and we do not store it on disk for security.
    // So on app reload, the user must log in again to unlock the vault.
    clearToken()
    setIsLoggedIn(false)
  }, [])

  const [isNotifOpen, setIsNotifOpen] = useState(false)
  const [notifications, setNotifications] = useState([])

  const fetchNotifications = async () => {
    try {
      const data = await api('/api/notifications')
      if (Array.isArray(data)) {
        setNotifications(data)
      }
    } catch (err) {
      console.error('Failed to fetch notifications:', err)
    }
  }

  useEffect(() => {
    if (!isLoggedIn) return

    const token = getToken()
    const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080'
    
    api('/api/orgs').then(data => setUserOrgs(data || [])).catch(console.error)
    fetchNotifications()

    // Real-time SSE Stream
    let evtSource = null
    try {
      evtSource = new EventSource(`${API_URL}/api/notifications/stream?token=${token}`)

      evtSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.notifications && Array.isArray(data.notifications)) {
            setNotifications(data.notifications)
          }
        } catch (err) {
          console.error("SSE parse error", err)
        }
      }

      evtSource.onerror = (err) => {
        // Fallback gracefully to interval polling
        if (evtSource) evtSource.close()
      }
    } catch (e) {
      console.warn("EventSource initialization failed, using polling fallback", e)
    }

    // Interval polling backup every 6 seconds
    const interval = setInterval(() => {
      fetchNotifications()
    }, 6000)

    return () => {
      if (evtSource) evtSource.close()
      clearInterval(interval)
    }
  }, [isLoggedIn])

  const handleMarkRead = async () => {
    try {
      await api('/api/notifications/read', { method: 'POST', body: JSON.stringify({ all: true }) })
      setNotifications(prev => prev.map(n => ({ ...n, is_read: true })))
    } catch (err) {}
  }

  const handleNotificationClick = async (n) => {
    setIsNotifOpen(false)
    if (!n.is_read) {
      // Tandai notifikasi spesifik ini sebagai terbaca di state lokal dan server
      setNotifications(prev => prev.map(item => item.id === n.id ? { ...item, is_read: true } : item))
      try {
        await api('/api/notifications/read', {
          method: 'POST',
          body: JSON.stringify({ id: Number(n.id) })
        })
      } catch (err) {
        console.error('Failed to mark notification as read:', err)
      }
    }
    if (n.type === 'file_share') {
      setCurrentView('decrypt')
    } else if (n.type === 'connection_request' || n.type === 'connection_accepted') {
      setCurrentView('connections')
    } else if (n.type === 'org_created' || n.type?.startsWith('org_')) {
      setCurrentView('org')
    }
  }

  const handleLogout = () => {
    clearToken()
    setUser(null)
    setMasterKey(null)
    setIsLoggedIn(false)
  }

  if (!isLoggedIn) {
    return (
      <div className="window">
        <Titlebar />
        <div style={{ flex: 1, overflow: 'auto' }}>
          <LoginView onLogin={(u, token, mKey) => { setUser(u); setMasterKey(mKey); setIsLoggedIn(true) }} />
        </div>
      </div>
    )
  }

  const unreadCount = notifications.filter(n => !n.is_read).length

  return (
    <div className="window">
      <Titlebar />
      <div className="shell">
        <Sidebar currentView={currentView} onNavigate={setCurrentView} user={user} userOrgs={userOrgs} activeOrg={activeOrg} setActiveOrg={setActiveOrg} />
        <main className="main">
          <div className="main-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', position: 'relative' }}>
            <div className="breadcrumb">Faycryptor / <b>{viewLabels[currentView]}</b></div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <div 
                className="notif-wrap" 
                onClick={() => { setIsNotifOpen(!isNotifOpen); if(!isNotifOpen) fetchNotifications(); }}
                style={{ cursor: 'pointer', background: 'var(--surface-2)', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border)', position: 'relative' }}
              >
                <Bell size={16} color="var(--text-secondary)" />
                {unreadCount > 0 && (
                  <div className="notif-dot" style={{ position: 'absolute', top: '3px', right: '3px', width: '7px', height: '7px', background: 'var(--danger)', borderRadius: '50%', border: '1px solid var(--surface)' }}></div>
                )}
              </div>
              <div style={{ cursor: 'pointer', background: 'var(--surface-2)', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border)' }}>
                <HelpCircle size={16} color="var(--text-secondary)" />
              </div>
            </div>

            {/* Notification Dropdown */}
            {isNotifOpen && (
              <div style={{ position: 'absolute', top: '44px', right: '16px', width: '340px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: '8px', boxShadow: '0 8px 24px rgba(0,0,0,0.35)', zIndex: 100, display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '13px' }}>
                    Notifikasi {unreadCount > 0 && <span style={{ background: 'var(--accent)', color: '#fff', padding: '1px 6px', borderRadius: '99px', fontSize: '10px', marginLeft: '6px' }}>{unreadCount}</span>}
                  </span>
                  {unreadCount > 0 && (
                    <button onClick={handleMarkRead} style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: '11px', cursor: 'pointer', fontWeight: 500 }}>Baca semua notifikasi</button>
                  )}
                </div>
                <div style={{ maxHeight: '320px', overflowY: 'auto', padding: '4px 0' }}>
                  {notifications.length === 0 ? (
                    <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>Belum ada notifikasi</div>
                  ) : (
                    notifications.map(n => (
                      <div 
                        key={n.id} 
                        onClick={() => handleNotificationClick(n)}
                        style={{
                          padding: '10px 14px', display: 'flex', gap: '10px', alignItems: 'flex-start',
                          background: n.is_read ? 'transparent' : 'rgba(94, 106, 210, 0.08)',
                          borderLeft: n.is_read ? '3px solid transparent' : '3px solid var(--accent)',
                          cursor: 'pointer', borderBottom: '1px solid var(--border)',
                          transition: 'background 0.15s ease'
                        }}
                      >
                        <div style={{ marginTop: '2px', color: n.is_read ? 'var(--text-muted)' : 'var(--accent)' }}>
                          <Bell size={14} />
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>{n.title}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: 1.4 }}>{n.message}</div>
                          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                            {new Date(n.created_at).toLocaleDateString('id-ID', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

          </div>
          <div className="main-body">
            <ErrorBoundary key={currentView}>
              {currentView === 'home' && <HomeView onNavigate={setCurrentView} user={user} />}
              {currentView === 'encrypt' && <EncryptView masterKey={masterKey} />}
              {currentView === 'decrypt' && <DecryptView user={user} masterKey={masterKey} />}
              {currentView === 'keys' && <KeysView user={user} masterKey={masterKey} />}
              {currentView === 'settings' && <SettingsView user={user} onLogout={handleLogout} />}
              {currentView === 'about' && <AboutView />}
              {(currentView === 'workspace' || currentView === 'org' || currentView === 'connections') && (
                <WorkspaceView
                  user={user}
                  masterKey={masterKey}
                  activeOrg={activeOrg}
                  setActiveOrg={setActiveOrg}
                  userOrgs={userOrgs}
                  fetchUserOrgs={() => api('/api/orgs').then(d => setUserOrgs(d || []))}
                  initialTab={currentView === 'connections' ? 'connections' : 'org'}
                />
              )}
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
