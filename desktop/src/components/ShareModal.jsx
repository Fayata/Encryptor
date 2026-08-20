import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Shield, Clock, Flame, Share2, Copy, Check, AlertTriangle, Lock } from 'lucide-react'

export default function ShareModal({ recipientUsername, masterKey, onClose }) {
  const [keys, setKeys] = useState([])
  const [selectedKey, setSelectedKey] = useState('')
  const [loading, setLoading] = useState(false)

  // Dynamic Rule States
  const [expiryPreset, setExpiryPreset] = useState('24h') // '1h', '24h', '3d', '7d', 'forever', 'custom'
  const [customHours, setCustomHours] = useState(12)
  const [oneTimeView, setOneTimeView] = useState(false)
  const [maxForward, setMaxForward] = useState(0)

  const [shareResult, setShareResult] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    // Fetch only vault files for sharing
    api('/api/keys')
      .then(data => {
        const allKeys = Array.isArray(data) ? data : (data?.keys || [])
        setKeys(allKeys.filter(k => k.file_path === 'db://vault'))
      })
      .catch(err => console.error(err))
  }, [])

  // Calculate expiration seconds
  const getExpirySeconds = () => {
    switch (expiryPreset) {
      case '1h': return 3600
      case '24h': return 86400
      case '3d': return 259200
      case '7d': return 604800
      case 'custom': return Math.max(1, customHours) * 3600
      case 'forever': return 0
      default: return 86400
    }
  }

  const handleShare = async () => {
    if (!selectedKey) return alert('Pilih file dari Vault terlebih dahulu.')

    setLoading(true)
    try {
      const expiresInSec = getExpirySeconds()
      const res = await api('/api/share', {
        method: 'POST',
        headers: {
          'X-Master-Key': masterKey
        },
        body: JSON.stringify({
          key_id: parseInt(selectedKey),
          recipient_username: recipientUsername,
          max_forward_count: maxForward,
          expires_in_seconds: expiresInSec,
          one_time_view: oneTimeView,
          scope: 'personal'
        })
      })

      if (res.share_password) {
        setShareResult({
          password: res.share_password,
          recipient: recipientUsername,
          oneTimeView: res.one_time_view,
          expiresAt: res.expires_at
        })
      } else {
        alert(`File berhasil dikirim ke ${recipientUsername}`)
        onClose()
      }
    } catch (err) {
      alert(`Gagal mengirim: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (!shareResult?.password) return
    navigator.clipboard.writeText(shareResult.password)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.65)', display: 'flex', alignItems: 'center',
      justifyContent: 'center', zIndex: 1000, padding: '16px'
    }}>
      <div className="panel" style={{ width: '480px', maxWidth: '100%', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        <div className="panel-head" style={{ borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '8px', padding: '16px 20px' }}>
          <Shield size={18} style={{ color: 'var(--accent)' }} />
          <span style={{ fontWeight: 600 }}>Kirim File Aman ke {recipientUsername}</span>
        </div>

        <div className="panel-body" style={{ overflowY: 'auto', padding: '20px' }}>
          {shareResult ? (
            <div style={{ textAlign: 'center', padding: '8px 0' }}>
              <div style={{
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                width: '48px', height: '48px', borderRadius: '50%',
                background: 'var(--success-tint)', color: 'var(--success)', marginBottom: '12px'
              }}>
                <Check size={24} />
              </div>
              <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                File Berhasil Dibagikan!
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: '20px' }}>
                Berikan password enkripsi di bawah ini kepada <strong>{shareResult.recipient}</strong> melalui jalur pribadi (WA/Telegram/Japri).
              </p>

              {/* Password Box */}
              <div style={{
                background: 'var(--surface-2)', padding: '16px 20px', borderRadius: '10px',
                border: '1px solid var(--border-strong)', marginBottom: '16px'
              }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
                  Password Share (Hanya Muncul Sekali)
                </div>
                <div style={{
                  fontSize: '24px', fontWeight: 700, letterSpacing: '3px',
                  fontFamily: 'monospace', color: 'var(--accent)', userSelect: 'all',
                  marginBottom: '12px'
                }}>
                  {shareResult.password}
                </div>
                <button
                  className="btn-secondary"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '6px',
                    fontSize: '12px', padding: '6px 16px', margin: '0 auto'
                  }}
                  onClick={handleCopy}
                >
                  {copied ? <Check size={14} style={{ color: 'var(--success)' }} /> : <Copy size={14} />}
                  {copied ? 'Tersalin ke Clipboard!' : 'Salin Password'}
                </button>
              </div>

              {/* Warning note */}
              <div style={{
                background: 'rgba(242,85,90,0.08)', border: '1px solid rgba(242,85,90,0.2)',
                borderRadius: '8px', padding: '10px 14px', textAlign: 'left',
                display: 'flex', alignItems: 'flex-start', gap: '10px', marginBottom: '20px'
              }}>
                <AlertTriangle size={16} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: '2px' }} />
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  <strong>Penting:</strong> Password ini <u>tidak disimpan di database</u>. Jika dialog ini ditutup tanpa disalin, penerima tidak akan bisa membuka file.
                </div>
              </div>

              <button className="btn-primary" style={{ width: '100%', padding: '10px' }} onClick={onClose}>
                Selesai & Tutup
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Select Vault File */}
              <div className="field">
                <label className="field-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={14} /> Pilih File dari Cloud Vault
                </label>
                <select
                  className="text-input"
                  value={selectedKey}
                  onChange={e => setSelectedKey(e.target.value)}
                  style={{ width: '100%', padding: '10px' }}
                >
                  <option value="">-- Pilih File --</option>
                  {keys.map(k => (
                    <option key={k.id} value={k.id}>{k.key_name}</option>
                  ))}
                </select>
                {keys.length === 0 && (
                  <div style={{ fontSize: '12px', color: 'var(--danger)', marginTop: '6px' }}>
                    Vault Anda masih kosong. Enkripsi dan upload file terlebih dahulu di menu Encrypt.
                  </div>
                )}
              </div>

              {/* Dynamic Expiration Rules */}
              <div className="field">
                <label className="field-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Clock size={14} /> Masa Berlaku Akses (Masa Simpan)
                </label>
                <div className="segmented" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '4px', marginBottom: '8px' }}>
                  {[
                    { id: '1h', label: '1 Jam' },
                    { id: '24h', label: '24 Jam' },
                    { id: '3d', label: '3 Hari' },
                    { id: '7d', label: '7 Hari' },
                    { id: 'custom', label: 'Kustom' },
                    { id: 'forever', label: 'Selamanya' }
                  ].map(opt => (
                    <button
                      key={opt.id}
                      type="button"
                      className={expiryPreset === opt.id ? 'active' : ''}
                      onClick={() => setExpiryPreset(opt.id)}
                      style={{ padding: '6px 8px', fontSize: '11px' }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>

                {expiryPreset === 'custom' && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Berlaku selama:</span>
                    <input
                      type="number"
                      min="1"
                      max="720"
                      className="text-input"
                      style={{ width: '80px', padding: '4px 8px', textAlign: 'center' }}
                      value={customHours}
                      onChange={e => setCustomHours(parseInt(e.target.value) || 1)}
                    />
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Jam</span>
                  </div>
                )}
              </div>

              {/* One-Time View (Burn After Reading) */}
              <div style={{
                background: oneTimeView ? 'rgba(242,85,90,0.08)' : 'var(--surface-2)',
                border: `1px solid ${oneTimeView ? 'rgba(242,85,90,0.3)' : 'var(--border)'}`,
                borderRadius: '8px', padding: '12px 14px',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                cursor: 'pointer', transition: 'all 0.2s ease'
              }} onClick={() => setOneTimeView(!oneTimeView)}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                  <Flame size={18} style={{ color: oneTimeView ? 'var(--danger)' : 'var(--text-muted)', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: oneTimeView ? 'var(--danger)' : 'var(--text-primary)' }}>
                      Akses Sekali Lihat (Self-Destruct)
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      File otomatis hangus dan hilang dari Vault penerima setelah 1x didekripsi.
                    </div>
                  </div>
                </div>
                <div className="switch" style={{ pointerEvents: 'none' }}>
                  <input type="checkbox" checked={oneTimeView} readOnly />
                  <label></label>
                </div>
              </div>

              {/* Forward Permissions */}
              <div className="field">
                <label className="field-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Share2 size={14} /> Izin Meneruskan (Forward)
                </label>
                <div className="segmented" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '4px' }}>
                  {[
                    { val: 0, label: 'Dilarang' },
                    { val: 1, label: 'Boleh 1x' },
                    { val: 2, label: 'Boleh 2x' }
                  ].map(opt => (
                    <button
                      key={opt.val}
                      type="button"
                      className={maxForward === opt.val ? 'active' : ''}
                      onClick={() => setMaxForward(opt.val)}
                      style={{ padding: '6px 8px', fontSize: '11px' }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Live Rule Summary Card */}
              <div style={{
                background: 'var(--surface-2)', borderRadius: '8px', padding: '12px 14px',
                border: '1px dashed var(--border-strong)', fontSize: '12px'
              }}>
                <div style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--text-secondary)' }}>
                 Ringkasan Aturan Pengiriman:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-muted)', fontSize: '11px' }}>
                  <div>• Masa Berlaku: <strong style={{ color: 'var(--text-primary)' }}>
                    {expiryPreset === 'forever' ? 'Tanpa batas waktu' : `${expiryPreset === 'custom' ? customHours + ' Jam' : expiryPreset}`}
                  </strong></div>
                  <div>• Mode Sekali Lihat: <strong style={{ color: oneTimeView ? 'var(--danger)' : 'var(--text-primary)' }}>
                    {oneTimeView ? 'AKTIF (Otomatis hangus setelah 1x buka)' : 'Nonaktif (Dapat dibuka berulang selama masa aktif)'}
                  </strong></div>
                  <div>• Izin Teruskan: <strong style={{ color: 'var(--text-primary)' }}>
                    {maxForward === 0 ? 'Hanya penerima pertama' : `Maksimal ${maxForward}x diteruskan`}
                  </strong></div>
                </div>
              </div>

              {/* Actions */}
              <div className="actions-row" style={{ marginTop: '8px' }}>
                <button type="button" className="btn-secondary" style={{ flex: 1 }} onClick={onClose}>
                  Batal
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  style={{ flex: 2 }}
                  onClick={handleShare}
                  disabled={loading || !selectedKey}
                >
                  {loading ? 'Mengunci & Mengirim...' : 'Kirim File dengan Aturan'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
