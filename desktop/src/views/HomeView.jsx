import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Lock, Unlock, Users } from 'lucide-react'

export default function HomeView({ onNavigate, user }) {
  const [stats, setStats] = useState({ vault_keys: 0, files_encrypted: 0, shared_with_me: 0 })
  const [activities, setActivities] = useState([])

  useEffect(() => {
    // Fetch stats
    api('/api/status')
      .then(data => setStats({ files_encrypted: data.keys_count || 0, vault_keys: data.keys_count || 0 }))
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
        const sorted = keys.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at)).slice(0, 5)
        setActivities(sorted)
      })
      .catch(err => console.error(err))
  }, [])

  return (
    <div style={{ display: 'flex', gap: '24px', height: '100%', alignItems: 'flex-start' }}>
      
      {/* ── Left Column (Main) ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '32px' }}>
        
        {/* Quick Actions (Tanpa Judul) */}
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
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>Encrypt</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Amankan file & folder</div>
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
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>Decrypt</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{stats.files_encrypted} file terenkripsi menunggu</div>
            </div>
          </div>

          <div 
            onClick={() => onNavigate('connections')}
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', cursor: 'pointer', transition: '0.2s' }}
            onMouseOver={e => e.currentTarget.style.borderColor = 'var(--text-muted)'}
            onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--surface-2)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Users size={18} style={{ color: 'var(--accent)' }} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '16px', marginBottom: '6px' }}>Koneksi Saya</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Kelola izin & akses file</div>
            </div>
          </div>

        </div>

        {/* Recent Activity */}
        <div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.5px', marginBottom: '12px', textTransform: 'uppercase' }}>
            Aktivitas Terbaru
          </div>
          
          <div style={{ border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--surface)' }}>
            {activities.length > 0 ? activities.map((act, i) => {
              const isDec = act.status === 'decrypted'
              const badgeColor = isDec ? 'var(--success)' : 'var(--accent)'
              const badgeBg = isDec ? 'var(--success-tint)' : 'var(--accent-tint)'
              const label = isDec ? 'DEC' : 'ENC'
              const actionText = isDec ? 'Anda mendekripsi' : 'Anda mengenkripsi'
              
              // Formatting time
              const date = new Date(act.updated_at)
              const now = new Date()
              const diffMs = now - date
              const diffHrs = Math.floor(diffMs / (1000 * 60 * 60))
              let timeStr = date.toLocaleDateString('id-ID')
              if (diffHrs === 0) timeStr = 'Baru saja'
              else if (diffHrs < 24) timeStr = `${diffHrs}j lalu`
              else if (diffHrs < 48) timeStr = 'Kemarin'

              return (
                <div key={act.id || i} style={{ display: 'flex', alignItems: 'center', padding: '12px 16px', borderBottom: i === activities.length - 1 ? 'none' : '1px solid var(--border)' }}>
                  <div style={{ fontSize: '10px', fontWeight: 600, color: badgeColor, background: badgeBg, padding: '2px 6px', borderRadius: '4px', marginRight: '12px' }}>{label}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 500, flex: 1 }}>{act.key_name}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{actionText}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginLeft: '12px', width: '70px', textAlign: 'right' }}>{timeStr}</div>
                </div>
              )
            }) : (
              <div style={{ padding: '24px', textAlign: 'center', fontSize: '13px', color: 'var(--text-muted)' }}>
                Belum ada aktivitas.
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
            Status Vault
          </div>
          <div style={{ padding: '8px 16px' }}>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>File terenkripsi</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.files_encrypted}</span>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Kunci di Web Vault</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.vault_keys}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Dibagikan ke Anda</span>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{stats.shared_with_me}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Koneksi vault</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--success)' }} />
                <span style={{ fontSize: '13px', color: 'var(--success)' }}>online</span>
              </div>
            </div>

          </div>
        </div>

        {/* Menunggu Respon */}
        <div style={{ border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--surface)' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 600, fontSize: '14px' }}>Menunggu Respon</span>
            <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: '11px', height: 'auto' }}>Lihat</button>
          </div>
          
          <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>
              Tidak ada undangan masuk.
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
