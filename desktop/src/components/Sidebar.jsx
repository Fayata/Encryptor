import React from 'react'
import {
  Home, Lock, Files, Building2, Users, Globe, Key, Settings, Info, ChevronDown, Shield
} from 'lucide-react'

export default function Sidebar({ currentView, onNavigate, user, userOrgs = [], activeOrg, setActiveOrg }) {
  const [wsOpen, setWsOpen] = React.useState(false)

  const navGroups = [
    {
      label: 'Overview',
      items: [{ id: 'home', icon: Home, text: 'Home' }]
    },
    {
      label: 'File Operations',
      items: [
        { id: 'encrypt', icon: Lock, text: 'Encrypt' },
        { id: 'decrypt', icon: Files, text: 'File' }
      ]
    },
    {
      label: 'Organisasi',
      items: [{ id: 'org', icon: Building2, text: 'Organisasi' }]
    },
    {
      label: 'Koneksi',
      items: [{ id: 'connections', icon: Users, text: 'Koneksi Saya' }]
    },
    {
      label: 'Web Vault',
      items: [
        { id: 'keys', icon: Key, text: 'View Keys' }
      ]
    },
    {
      label: 'General',
      items: [
        { id: 'settings', icon: Settings, text: 'Settings' },
        { id: 'about', icon: Info, text: 'About' }
      ]
    }
  ]

  return (
    <div className="sidebar">
      <div className="workspace" onClick={() => setWsOpen(!wsOpen)} style={{ cursor: 'pointer', position: 'relative', zIndex: 50 }}>
        <div className="ws-wrap">
          <div className="ws-mark">
            <Shield size={16} />
          </div>
          <div className="ws-name">{activeOrg ? activeOrg.name : (userOrgs.length > 0 ? 'Pilih Organisasi...' : 'Fayata Organization')}</div>
          <ChevronDown size={14} className="ws-chevron" />
        </div>
        {wsOpen && (
          <div className="ws-menu">
            {userOrgs.map(org => (
              <button key={org.id} className="ws-item" onClick={(e) => { 
                e.stopPropagation(); 
                setActiveOrg(org); 
                setWsOpen(false); 
              }}>
                {org.name}
              </button>
            ))}

            <div style={{ height: '1px', background: 'var(--border)', margin: '4px 0' }} />

            <button className="ws-item" onClick={(e) => { e.stopPropagation(); setWsOpen(false); onNavigate('org'); }}>
              Buat Organisasi...
            </button>
          </div>
        )}
      </div>
      <div className="nav-group">
        {navGroups.map((group, idx) => (
          <React.Fragment key={idx}>
            <div className="nav-label">{group.label}</div>
            {group.items.map(item => {
              const Icon = item.icon
              return (
                <button
                  key={item.id}
                  className={`nav-item ${currentView === item.id ? 'active' : ''}`}
                  onClick={() => onNavigate(item.id)}
                  style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', fontFamily: 'inherit', fontSize: '13px' }}
                >
                  <Icon size={16} />
                  <span>{item.text}</span>
                </button>
              )
            })}
          </React.Fragment>
        ))}
      </div>
      <div className="sidebar-footer">
        <div className="avatar">
          {user?.username ? user.username.charAt(0).toUpperCase() : 'U'}
        </div>
        <div className="footer-info">
          <strong>{user?.username || 'User'}</strong>
          <span>Vault connected</span>
        </div>
        <div className="footer-dot"></div>
      </div>
    </div>
  )
}
