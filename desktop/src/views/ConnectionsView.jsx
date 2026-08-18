import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Users, UserPlus, Check, X, Send } from 'lucide-react'
import ShareModal from '../components/ShareModal'

export default function ConnectionsView({ user }) {
  const [connections, setConnections] = useState([])
  const [usernameInput, setUsernameInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState({ text: '', type: '' })
  const [shareRecipient, setShareRecipient] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)

  const fetchConnections = () => {
    api('/api/connections')
      .then(data => setConnections(data || []))
      .catch(err => console.error(err))
  }

  useEffect(() => {
    fetchConnections()
  }, [])

  const handleRequest = async (e) => {
    e.preventDefault()
    if (!usernameInput) return
    setLoading(true)
    setMessage({ text: '', type: '' })
    try {
      await api('/api/connections/request', {
        method: 'POST',
        body: JSON.stringify({ username: usernameInput })
      })
      setMessage({ text: 'Permintaan koneksi berhasil dikirim.', type: 'success' })
      setUsernameInput('')
      fetchConnections()
    } catch (err) {
      setMessage({ text: err.message || 'Gagal mengirim permintaan', type: 'error' })
    }
    setLoading(false)
  }

  const handleAccept = async (connId) => {
    try {
      await api('/api/connections/accept', {
        method: 'POST',
        body: JSON.stringify({ connection_id: connId })
      })
      fetchConnections()
    } catch (err) {
      alert(err.message || 'Gagal menerima koneksi')
    }
  }

  const activeConnections = connections.filter(c => c.status === 'accepted')
  const pendingRequests = connections.filter(c => c.status === 'pending' && c.recipient_id === user?.id)
  
  const itemsPerPage = 10
  const totalPages = Math.ceil(activeConnections.length / itemsPerPage)
  const currentActiveConnections = activeConnections.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      {shareRecipient && (
        <ShareModal 
          recipientUsername={shareRecipient} 
          onClose={() => setShareRecipient(null)} 
        />
      )}
      <div className="panel">
        <div className="panel-head">Tambah Koneksi</div>
        <div className="panel-body">
          <form onSubmit={handleRequest} style={{ display: 'flex', gap: '12px' }}>
            <input 
              type="text" 
              className="text-input" 
              placeholder="Masukkan username teman..." 
              value={usernameInput} 
              onChange={e => setUsernameInput(e.target.value)}
              style={{ flex: 1 }}
            />
            <button type="submit" className="btn-primary" disabled={loading || !usernameInput}>
              <UserPlus size={16} style={{ marginRight: '6px' }} />
              Kirim Permintaan
            </button>
          </form>
          {message.text && (
            <div style={{ marginTop: '12px', fontSize: '13px', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
              {message.text}
            </div>
          )}
        </div>
      </div>

      {pendingRequests.length > 0 && (
        <div className="panel" style={{ borderColor: 'var(--accent)' }}>
          <div className="panel-head" style={{ color: 'var(--accent)' }}>Menunggu Persetujuan Anda</div>
          <div className="panel-body" style={{ padding: 0 }}>
            {pendingRequests.map(c => (
              <div key={c.id} style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--surface-2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Users size={16} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 600 }}>User ID: {c.requester_id}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Ingin terhubung dengan Anda</div>
                  </div>
                </div>
                <button className="btn-primary" onClick={() => handleAccept(c.id)} style={{ padding: '6px 12px', height: 'auto' }}>
                  <Check size={14} style={{ marginRight: '6px' }} /> Terima
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">Daftar Koneksi Aktif</div>
        <div className="panel-body" style={{ padding: 0 }}>
          {activeConnections.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>Anda belum memiliki koneksi aktif.</div>
          ) : (
            currentActiveConnections.map(c => {
              const friendId = c.requester_id === user?.id ? c.recipient_id : c.requester_id;
              return (
                <div key={c.id} style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: c === currentActiveConnections[currentActiveConnections.length - 1] ? 'none' : '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--accent-tint)', color: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
                      {friendId}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>User ID: {friendId}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Terhubung sejak {new Date(c.created_at).toLocaleDateString()}</div>
                    </div>
                  </div>
                  <button 
                    className="btn-secondary" 
                    style={{ padding: '6px 12px', height: 'auto' }}
                    onClick={() => setShareRecipient(String(friendId))}
                  >
                    <Send size={14} style={{ marginRight: '6px' }} /> Kirim File
                  </button>
                </div>
              )
            })
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
    </div>
  )
}
