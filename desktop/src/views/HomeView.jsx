import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Lock, Unlock, Users } from 'lucide-react'
import { useTranslation } from '../lib/i18n'

function formatRelativeTime(dateInput, nowTimestamp, language) {
  if (!dateInput) return ''
  const date = new Date(dateInput)
  const diffMs = nowTimestamp - date.getTime()
  if (diffMs < 0) return language === 'en' ? 'Just now' : 'Baru saja'

  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHrs = Math.floor(diffMin / 60)
  const diffDays = Math.floor(diffHrs / 24)

  if (diffSec < 45) {
    return language === 'en' ? 'Just now' : 'Baru saja'
  }
  if (diffMin < 60) {
    return language === 'en' ? `${diffMin}m ago` : `${diffMin}m lalu`
  }
  if (diffHrs < 24) {
    return language === 'en' ? `${diffHrs}h ago` : `${diffHrs}j lalu`
  }
  if (diffDays === 1) {
    return language === 'en' ? 'Yesterday' : 'Kemarin'
  }
  if (diffDays < 7) {
    return language === 'en' ? `${diffDays}d ago` : `${diffDays} hari lalu`
  }
  return date.toLocaleDateString(language === 'en' ? 'en-US' : 'id-ID', {
    day: '2-digit',
    month: 'short',
    year: 'numeric'
  })
}

export default function HomeView({ onNavigate, user }) {
  const { t, language } = useTranslation()
  const [stats, setStats] = useState({ vault_keys: 0, files_encrypted: 0, shared_with_me: 0 })
  const [activities, setActivities] = useState([])
  const [now, setNow] = useState(Date.now())

  const fetchData = () => {
    api('/api/status')
      .then(data => setStats(prev => ({
        ...prev,
        files_encrypted: data.keys_count || 0,
        vault_keys: data.keys_count || 0
      })))
      .catch(err => console.error(err))
      
    api('/api/keys')
      .then(data => {
        const keys = Array.isArray(data) ? data : (data?.keys || [])
        // Calculate real stats from keys
        const encryptedCount = keys.filter(k => (k.status || 'encrypted') === 'encrypted').length
        setStats({
          vault_keys: keys.length,
          files_encrypted: encryptedCount,
          shared_with_me: 0
        })

        // Sort by updated_at descending and take top 5
        const sorted = [...keys].sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at)).slice(0, 5)
        setActivities(sorted)
      })
      .catch(err => console.error(err))
  }

  useEffect(() => {
    fetchData()

    // 1. Live ticker for relative time every 10 seconds
    const tickerInterval = setInterval(() => {
      setNow(Date.now())
    }, 10000)

    // 2. Real-time data polling every 4 seconds for fresh vault & activities stats
    const pollInterval = setInterval(() => {
      fetchData()
    }, 4000)

    // 3. Refetch when window regains focus
    const handleFocus = () => {
      setNow(Date.now())
      fetchData()
    }
    window.addEventListener('focus', handleFocus)

    return () => {
      clearInterval(tickerInterval)
      clearInterval(pollInterval)
      window.removeEventListener('focus', handleFocus)
    }
  }, [])

  return (
    <div style={{ display: 'flex', gap: '24px', height: '100%', alignItems: 'flex-start' }}>
      
      {/* ── Left Column (Main) ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '32px' }}>
        
        {/* Quick Actions */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          
          <div 
            onClick={() => onNavigate('encrypt')}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', cursor: 'pointer', transition: '0.2s' }}
            onMouseOver={e => e.currentTarget.style.borderColor = 'var(--text-muted)'}
            onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--surface-2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Lock size={18} style={{ color: 'var(--accent)' }} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>{t('home.encryptCardTitle')}</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{t('home.encryptCardDesc')}</div>
            </div>
          </div>

          <div 
            onClick={() => onNavigate('decrypt')}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', cursor: 'pointer', transition: '0.2s' }}
            onMouseOver={e => e.currentTarget.style.borderColor = 'var(--text-muted)'}
            onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--surface-2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Unlock size={18} style={{ color: 'var(--accent)' }} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>{t('home.decryptCardTitle')}</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{t('home.decryptCardDesc')}</div>
            </div>
          </div>

          <div 
            onClick={() => onNavigate('workspace')}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', cursor: 'pointer', transition: '0.2s' }}
            onMouseOver={e => e.currentTarget.style.borderColor = 'var(--text-muted)'}
            onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--surface-2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Users size={18} style={{ color: 'var(--accent)' }} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>{t('home.workspaceCardTitle')}</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{t('home.workspaceCardDesc')}</div>
            </div>
          </div>

        </div>

        {/* Recent Activity */}
        <div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.5px', marginBottom: '12px', textTransform: 'uppercase' }}>
            {t('home.recentActivity')}
          </div>
          
          <div style={{ border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--surface)' }}>
            {activities.length > 0 ? activities.map((act, i) => {
              const isDec = act.status === 'decrypted'
              const badgeColor = isDec ? 'var(--success)' : 'var(--accent)'
              const badgeBg = isDec ? 'var(--success-tint)' : 'var(--accent-tint)'
              const label = isDec ? 'DEC' : 'ENC'
              const actionText = isDec 
                ? (language === 'en' ? 'You decrypted' : 'Anda mendekripsi')
                : (language === 'en' ? 'You encrypted' : 'Anda mengenkripsi')
              
              const timeStr = formatRelativeTime(act.updated_at, now, language)

              return (
                <div key={act.id || i} style={{ display: 'flex', alignItems: 'center', padding: '12px 16px', borderBottom: i === activities.length - 1 ? 'none' : '1px solid var(--border)' }}>
                  <div style={{ fontSize: '10px', fontWeight: 600, color: badgeColor, background: badgeBg, padding: '2px 6px', borderRadius: '4px', marginRight: '12px' }}>{label}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 500, flex: 1 }}>{act.key_name}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{actionText}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginLeft: '12px', width: '80px', textAlign: 'right' }}>{timeStr}</div>
                </div>
              )
            }) : (
              <div style={{ padding: '24px', textAlign: 'center', fontSize: '13px', color: 'var(--text-muted)' }}>
                {t('home.noActivity')}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* ── Right Column (Sidebar Panels) ── */}
      <div style={{ width: '300px', display: 'flex', flexDirection: 'column', gap: '16px', flexShrink: 0 }}>
        
        {/* Status Vault */}
        <div style={{ border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--surface)' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border)', fontWeight: 600, fontSize: '14px' }}>
            {language === 'en' ? 'Vault Status' : 'Status Vault'}
          </div>
          <div style={{ padding: '8px 16px' }}>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{language === 'en' ? 'Encrypted files' : 'File terenkripsi'}</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.files_encrypted}</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{language === 'en' ? 'Keys in Web Vault' : 'Kunci di Web Vault'}</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.vault_keys}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{language === 'en' ? 'Shared with you' : 'Dibagikan ke Anda'}</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.shared_with_me}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{language === 'en' ? 'Vault connection' : 'Koneksi vault'}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--success)' }} />
                <span style={{ fontSize: '13px', color: 'var(--success)' }}>online</span>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  )
}
