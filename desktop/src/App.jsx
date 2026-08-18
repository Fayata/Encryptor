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
import ConnectionsView from './views/ConnectionsView'
import OrganizationView from './views/OrganizationView'

const viewLabels = {
  home: 'Home', encrypt: 'Encrypt', decrypt: 'File',
  org: 'Organisasi', connections: 'Koneksi Saya',
  keys: 'View Keys', settings: 'Settings', about: 'About'
}

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
  const [currentView, setCurrentView] = useState('home')
  const [user, setUser] = useState(null)
  const [masterKey, setMasterKey] = useState(null)
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [userOrgs, setUserOrgs] = useState([])
  const [activeOrg, setActiveOrg] = useState(null)

  useEffect(() => {
    // We cannot auto-login because the Master Key (derived from password) 
    // must be kept in memory and we do not store it on disk for security.
    // So on app reload, the user must log in again to unlock the vault.
    clearToken()
    setIsLoggedIn(false)
  }, [])

  const [isNotifOpen, setIsNotifOpen] = useState(false)
  const [notifications, setNotifications] = useState([])

  useEffect(() => {
    if (!isLoggedIn) return

    const token = getToken()
    const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080'
    
    api('/api/orgs').then(data => setUserOrgs(data || [])).catch(console.error)

    const evtSource = new EventSource(`${API_URL}/api/notifications/stream?token=${token}`)

    evtSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.notifications) {
          setNotifications(data.notifications)
        }
      } catch (err) {
        console.error("SSE parse error", err)
      }
    }

    evtSource.onerror = (err) => {
      console.error("EventSource failed:", err)
      evtSource.close()
    }

    return () => {
      evtSource.close()
    }
  }, [isLoggedIn])

  const handleMarkRead = async () => {
    try {
      await api('/api/notifications/read', { method: 'POST' })
      setNotifications(prev => prev.map(n => ({ ...n, is_read: true })))
    } catch (err) {}
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
                style={{ cursor: 'pointer', background: 'var(--surface-2)', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border)' }}
              >
                <Bell size={16} color="var(--text-secondary)" />
                {unreadCount > 0 && <div className="notif-dot" style={{ position: 'absolute', top: '4px', right: '4px', width: '6px', height: '6px', background: 'var(--danger)', borderRadius: '50%' }}></div>}
              </div>
              <div style={{ cursor: 'pointer', background: 'var(--surface-2)', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border)' }}>
                <HelpCircle size={16} color="var(--text-secondary)" />
              </div>
            </div>

            {/* Notification Dropdown */}
            {isNotifOpen && (
              <div style={{ position: 'absolute', top: '40px', right: '16px', width: '320px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: '8px', boxShadow: '0 4px 12px rgba(0,0,0,0.2)', zIndex: 100, display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '13px' }}>Notifikasi</span>
                  {unreadCount > 0 && (
                    <button onClick={handleMarkRead} style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: '11px', cursor: 'pointer' }}>Tandai sudah dibaca</button>
                  )}
                </div>
                <div style={{ maxHeight: '300px', overflowY: 'auto', padding: '8px 0' }}>
                  {notifications.length === 0 ? (
                    <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>Belum ada notifikasi</div>
                  ) : (
                    notifications.map(n => (
                      <div key={n.id} style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '4px', background: n.is_read ? 'transparent' : 'rgba(94, 106, 210, 0.05)', borderLeft: n.is_read ? '2px solid transparent' : '2px solid var(--accent)' }}>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{n.title}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{n.message}</div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>{new Date(n.created_at).toLocaleString()}</div>
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
              {currentView === 'org' && <OrganizationView user={user} activeOrg={activeOrg} setActiveOrg={setActiveOrg} userOrgs={userOrgs} fetchUserOrgs={() => api('/api/orgs').then(d => setUserOrgs(d || []))} />}
              {currentView === 'connections' && <ConnectionsView user={user} />}
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
