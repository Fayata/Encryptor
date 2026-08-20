import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Building2, Plus, Users } from 'lucide-react'
import ShareModal from '../components/ShareModal'

export default function OrganizationView({ user, masterKey, activeOrg, setActiveOrg, userOrgs, fetchUserOrgs }) {
  const [formMode, setFormMode] = useState('none') // 'none', 'create', 'join'
  const [orgName, setOrgName] = useState('')
  const [orgDesc, setOrgDesc] = useState('')
  const [inviteCode, setInviteCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [members, setMembers] = useState([])
  const [currentPage, setCurrentPage] = useState(1)
  const [shareRecipient, setShareRecipient] = useState(null)
  
  const itemsPerPage = 10
  const totalPages = Math.ceil(members.length / itemsPerPage)
  const currentMembers = members.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

  useEffect(() => {
    if (activeOrg) {
      setCurrentPage(1)
      api(`/api/orgs/${activeOrg.id}/members`)
        .then(data => setMembers(data || []))
        .catch(err => console.error(err))
    }
  }, [activeOrg])

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!orgName) return
    setLoading(true)
    try {
      const data = await api('/api/orgs', {
        method: 'POST',
        body: JSON.stringify({ name: orgName, description: orgDesc })
      })
      setOrgName('')
      setOrgDesc('')
      setFormMode('none')
      if (fetchUserOrgs) await fetchUserOrgs()
      setActiveOrg(data) // Auto-switch to new org
    } catch (err) {
      alert(err.message || 'Gagal membuat organisasi')
    }
    setLoading(false)
  }

  const handleJoin = async (e) => {
    e.preventDefault()
    if (!inviteCode) return
    setLoading(true)
    // Mock functionality as per user request to defer backend
    alert("Fitur bergabung dengan kode undangan (" + inviteCode + ") sedang dalam tahap pengembangan!")
    setInviteCode('')
    setFormMode('none')
    setLoading(false)
  }

  const handleLeave = async () => {
    if (!activeOrg) return
    if (!window.confirm(`Yakin ingin keluar dari organisasi "${activeOrg.name}"?`)) return
    
    try {
      await api(`/api/orgs/${activeOrg.id}/leave`, { method: 'POST' })
      setActiveOrg(null)
      if (fetchUserOrgs) fetchUserOrgs()
    } catch (err) {
      alert(err.message || 'Gagal keluar dari organisasi')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      
      {shareRecipient && (
        <ShareModal 
          recipientUsername={shareRecipient} 
          masterKey={masterKey}
          onClose={() => setShareRecipient(null)} 
        />
      )}

      {!activeOrg ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', marginTop: '60px', gap: '20px' }}>
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px', lineHeight: '1.6' }}>
            Anda saat ini berada di <b>Personal Workspace</b>.<br/>
            Gunakan menu dropdown di kiri atas untuk berpindah konteks organisasi.
          </div>

          {formMode === 'none' && (
            <div style={{ display: 'flex', gap: '12px' }}>
              <button className="btn-primary" onClick={() => setFormMode('join')}>
                Gabung Organisasi
              </button>
              <button className="btn-secondary" onClick={() => setFormMode('create')}>
                <Plus size={16} style={{ marginRight: '6px' }} /> Buat Organisasi
              </button>
            </div>
          )}

          {formMode === 'join' && (
            <div className="panel" style={{ background: 'var(--surface-2)', width: '100%', maxWidth: '400px', textAlign: 'left' }}>
              <div className="panel-head">Gabung ke Organisasi</div>
              <div className="panel-body">
                <form onSubmit={handleJoin} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <input type="text" className="text-input" placeholder="Masukkan Kode Undangan" value={inviteCode} onChange={e => setInviteCode(e.target.value)} required />
                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                    <button type="button" className="btn-secondary" onClick={() => setFormMode('none')}>Batal</button>
                    <button type="submit" className="btn-primary" disabled={loading || !inviteCode}>Gabung</button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {formMode === 'create' && (
            <div className="panel" style={{ background: 'var(--surface-2)', width: '100%', maxWidth: '400px', textAlign: 'left' }}>
              <div className="panel-head">Buat Organisasi Baru</div>
              <div className="panel-body">
                <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <input type="text" className="text-input" placeholder="Nama Organisasi" value={orgName} onChange={e => setOrgName(e.target.value)} required />
                  <textarea className="text-input" placeholder="Deskripsi Singkat" value={orgDesc} onChange={e => setOrgDesc(e.target.value)} rows={2} />
                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                    <button type="button" className="btn-secondary" onClick={() => setFormMode('none')}>Batal</button>
                    <button type="submit" className="btn-primary" disabled={loading || !orgName}>Simpan</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="panel">
            <div className="panel-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Building2 size={16} />
                <span>Anggota: {activeOrg.name}</span>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="btn-primary" style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>+ Undang Member</button>
                <button className="btn-secondary" onClick={handleLeave} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px', color: 'var(--danger)', borderColor: 'var(--danger)' }}>Keluar</button>
              </div>
            </div>
            <div className="panel-body" style={{ padding: 0 }}>
              {members.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>Belum ada anggota.</div>
              ) : (
                currentMembers.map((m, i) => (
                  <div key={i} style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: i === currentMembers.length - 1 ? 'none' : '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--surface-2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <Users size={16} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 600 }}>Username: {m.username}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>Role: {m.role}</div>
                      </div>
                    </div>
                    {m.username !== user?.username && (
                      <button className="btn-secondary" style={{ padding: '4px 12px', height: 'auto', fontSize: '12px' }} onClick={() => setShareRecipient(m.username)}>
                        Kirim File
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--surface)', borderBottomLeftRadius: '8px', borderBottomRightRadius: '8px' }}>
                <button className="btn-secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>&larr; Prev</button>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Halaman {currentPage} dari {totalPages}</div>
                <button className="btn-secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>Next &rarr;</button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
