import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'

export default function ShareModal({ recipientUsername, onClose }) {
  const [keys, setKeys] = useState([])
  const [selectedKey, setSelectedKey] = useState('')
  const [maxForward, setMaxForward] = useState(0)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    // Fetch only vault files for sharing
    api('/api/keys')
      .then(data => {
        const allKeys = Array.isArray(data) ? data : (data?.keys || [])
        // Vault files are stored with file_path 'db://vault'
        setKeys(allKeys.filter(k => k.file_path === 'db://vault'))
      })
      .catch(err => console.error(err))
  }, [])

  const handleShare = async () => {
    if (!selectedKey) return alert('Pilih file dari Vault')
    
    setLoading(true)
    try {
      await api('/api/share', {
        method: 'POST',
        body: JSON.stringify({
          key_id: parseInt(selectedKey),
          recipient_username: recipientUsername,
          max_forward_count: maxForward,
          scope: 'personal' // simplified
        })
      })
      alert(`File berhasil dikirim ke ${recipientUsername}`)
      onClose()
    } catch (err) {
      alert(`Gagal mengirim: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, 
      background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', 
      justifyContent: 'center', zIndex: 1000
    }}>
      <div className="panel" style={{ width: '400px', maxWidth: '90%' }}>
        <div className="panel-head" style={{ borderBottom: '1px solid var(--border)' }}>
          Kirim File ke {recipientUsername}
        </div>
        <div className="panel-body">
          
          <div className="field">
            <label className="field-label">Pilih File dari Cloud Vault</label>
            <select 
              className="text-input" 
              value={selectedKey} 
              onChange={e => setSelectedKey(e.target.value)}
              style={{ width: '100%', padding: '8px' }}
            >
              <option value="">-- Pilih File --</option>
              {keys.map(k => (
                <option key={k.id} value={k.id}>{k.key_name}</option>
              ))}
            </select>
            {keys.length === 0 && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Vault Anda kosong. Upload file ke Cloud Vault di menu Encrypt.
              </div>
            )}
          </div>

          <div className="field">
            <label className="field-label">Share Rule (Batas Teruskan)</label>
            <div className="segmented" style={{ flexWrap: 'wrap' }}>
              <button 
                className={maxForward === 0 ? 'active' : ''} 
                onClick={() => setMaxForward(0)}
              >
                Hanya Penerima
              </button>
              <button 
                className={maxForward === 1 ? 'active' : ''} 
                onClick={() => setMaxForward(1)}
              >
                Boleh 1x Forward
              </button>
              <button 
                className={maxForward === 2 ? 'active' : ''} 
                onClick={() => setMaxForward(2)}
              >
                Boleh 2x Forward
              </button>
            </div>
          </div>

          <div className="actions-row" style={{ marginTop: '24px' }}>
            <button className="btn-secondary" onClick={onClose}>Batal</button>
            <button className="btn-primary" onClick={handleShare} disabled={loading || !selectedKey}>
              {loading ? 'Mengirim...' : 'Kirim File'}
            </button>
          </div>

        </div>
      </div>
    </div>
  )
}
