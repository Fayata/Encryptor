import React from 'react'
import {
  Home, Lock, Files, Building2, Users, Globe, Key, Settings, Info, ChevronDown, Shield
} from 'lucide-react'
import { useTranslation } from '../lib/i18n'

export default function Sidebar({ currentView, onNavigate, user, userOrgs = [], activeOrg, setActiveOrg }) {
  const { t } = useTranslation()
  const [wsOpen, setWsOpen] = React.useState(false)

  const navGroups = [
    {
      label: t('nav.overview'),
      items: [{ id: 'home', icon: Home, text: t('nav.home') }]
    },
    {
      label: t('nav.fileOps'),
      items: [
        { id: 'encrypt', icon: Lock, text: t('nav.encrypt') },
        { id: 'decrypt', icon: Files, text: t('nav.file') },
        { id: 'keys', icon: Key, text: t('nav.keys') }
      ]
    },
    {
      label: t('nav.collaboration'),
      items: [{ id: 'workspace', icon: Building2, text: t('nav.workspace') }]
    },
    {
      label: t('nav.general'),
      items: [
        { id: 'settings', icon: Settings, text: t('nav.settings') },
        { id: 'about', icon: Info, text: t('nav.about') }
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
          <div className="ws-name">{activeOrg ? activeOrg.name : t('nav.personal')}</div>
          <ChevronDown size={14} className="ws-chevron" />
        </div>
        {wsOpen && (
          <div className="ws-menu">
            <button className={`ws-item ${!activeOrg ? 'active' : ''}`} onClick={(e) => { 
              e.stopPropagation(); 
              setActiveOrg(null); 
              setWsOpen(false); 
            }}>
              {t('nav.personal')}
            </button>

            {userOrgs.length > 0 && <div style={{ height: '1px', background: 'var(--border)', margin: '4px 0' }} />}

            {userOrgs.map(org => (
              <button key={org.id} className={`ws-item ${activeOrg?.id === org.id ? 'active' : ''}`} onClick={(e) => { 
                e.stopPropagation(); 
                setActiveOrg(org); 
                setWsOpen(false); 
              }}>
                {org.name}
              </button>
            ))}

            <div style={{ height: '1px', background: 'var(--border)', margin: '4px 0' }} />

            <button className="ws-item" onClick={(e) => { e.stopPropagation(); setWsOpen(false); onNavigate('workspace'); }}>
              {t('nav.createOrg')}
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
          <span>{t('nav.vaultConnected')}</span>
        </div>
        <div className="footer-dot"></div>
      </div>
    </div>
  )
}
