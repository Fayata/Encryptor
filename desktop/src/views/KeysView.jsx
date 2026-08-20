import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Key, Eye, EyeOff, Trash2, Edit3, X, Download } from 'lucide-react'
import { useTranslation } from '../lib/i18n'

// Dekripsi encryption_password menggunakan masterKey (AES-256-GCM)
// Format ciphertext dari Go: [12-byte nonce][ciphertext + 16-byte auth tag] — semua hex-encoded
async function decryptPassword(encHex, masterKeyHex) {
  if (!encHex || !masterKeyHex) return null
  try {
    const encBytes = Uint8Array.from(encHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    const masterKeyBytes = Uint8Array.from(masterKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw', masterKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    )

    // 12 byte pertama = nonce, sisanya = ciphertext + auth tag
    const iv = encBytes.slice(0, 12)
    const ciphertext = encBytes.slice(12)

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, cryptoKey, ciphertext
    )
    return new TextDecoder().decode(decrypted)
  } catch {
    return null // masterKey salah atau data korup
  }
}

export default function KeysView({ user, masterKey }) {
  const { t, language } = useTranslation()
  const [keys, setKeys] = useState([])
  const [visibleKeys, setVisibleKeys] = useState({})
  const [decryptedPasswords, setDecryptedPasswords] = useState({}) // id -> plaintext password
  const [tab, setTab] = useState('vault') // always vault
  const [loadingId, setLoadingId] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)

  // Edit Password Modal State
  const [editModalKey, setEditModalKey] = useState(null)
  const [newPasswordInput, setNewPasswordInput] = useState('')
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [isUpdating, setIsUpdating] = useState(false)

  useEffect(() => {
    setCurrentPage(1)
  }, [tab])

  useEffect(() => {
    fetchKeys()
  }, [])

  const fetchKeys = () => {
    api('/api/keys?mine=true')
      .then(data => {
        const rawList = Array.isArray(data) ? data : (data?.keys || [])
        // Filter strictly to author/owner keys (never display shared files from connections or org members)
        const authorOnly = rawList.filter(k => {
          if (user?.id && k.user_id && k.user_id !== user.id) return false
          if (user?.username && k.author && k.author !== user.username) return false
          return true
        })
        setKeys(authorOnly)
      })
      .catch(err => console.error(err))
  }

  const toggleVisibility = async (id, encPasswordHex) => {
    if (visibleKeys[id]) {
      // Sembunyikan lagi
      setVisibleKeys(prev => ({ ...prev, [id]: false }))
      return
    }
    // Dekripsi baru, simpan ke state
    const plaintext = await decryptPassword(encPasswordHex, masterKey)
    setDecryptedPasswords(prev => ({ ...prev, [id]: plaintext }))
    setVisibleKeys(prev => ({ ...prev, [id]: true }))
  }

  const handleDownload = async (keyData) => {
    try {
      setLoadingId(keyData.id)
      const token = localStorage.getItem('api_token')
      const res = await fetch('http://127.0.0.1:8080/api/vault/download', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': token,
          'X-Master-Key': masterKey
        },
        body: JSON.stringify({ key_id: keyData.id })
      })

      if (!res.ok) {
        throw new Error(await res.text())
      }

      let filename = keyData.key_name || 'downloaded_file.fay'
      const disposition = res.headers.get('content-disposition')
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const matches = /filename="([^"]+)"/.exec(disposition)
        if (matches != null && matches[1]) {
          filename = matches[1]
        }
      }

      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.style.display = 'none'
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      alert(`Download Error: ${err.message}`)
    } finally {
      setLoadingId(null)
    }
  }

  const handleDelete = async (keyData) => {
    const keyName = keyData.key_name || `Key #${keyData.id}`
    if (!window.confirm(`Apakah Anda yakin ingin menghapus file/key "${keyName}"? File di vault dan akses terkait akan dihapus secara permanen.`)) {
      return
    }

    try {
      setLoadingId(keyData.id)
      await api(`/api/keys/${keyData.id}`, {
        method: 'DELETE'
      })
      setKeys(prev => prev.filter(k => k.id !== keyData.id))
      setDecryptedPasswords(prev => {
        const copy = { ...prev }
        delete copy[keyData.id]
        return copy
      })
      setVisibleKeys(prev => {
        const copy = { ...prev }
        delete copy[keyData.id]
        return copy
      })
    } catch (err) {
      alert(`Gagal menghapus file/key: ${err.message}`)
    } finally {
      setLoadingId(null)
    }
  }

  const openUpdatePasswordModal = (keyData) => {
    setEditModalKey(keyData)
    setNewPasswordInput('')
    setShowNewPassword(false)
  }

  const handleSavePassword = async () => {
    if (!editModalKey) return
    try {
      setIsUpdating(true)
      await api(`/api/keys/${editModalKey.id}`, {
        method: 'PUT',
        headers: {
          'X-Master-Key': masterKey
        },
        body: JSON.stringify({
          password: newPasswordInput
        })
      })

      // Invalidate plaintext decrypted cache for this key
      setDecryptedPasswords(prev => {
        const copy = { ...prev }
        delete copy[editModalKey.id]
        return copy
      })
      setVisibleKeys(prev => ({ ...prev, [editModalKey.id]: false }))
      setEditModalKey(null)
      fetchKeys()
    } catch (err) {
      alert(`Gagal mengupdate password: ${err.message}`)
    } finally {
      setIsUpdating(false)
    }
  }

  const localKeys = keys.filter(k => k.file_path !== 'db://vault')
  const vaultKeys = keys.filter(k => k.file_path === 'db://vault')

  const currentData = tab === 'local' ? localKeys : vaultKeys
  const itemsPerPage = 10
  const totalPages = Math.ceil(currentData.length / itemsPerPage)
  const paginatedData = currentData.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

  const renderTable = (data) => (
    <>
      <table className="data-table">
      <thead>
        <tr>
          <th>{t('keys.colFileName')}</th>
          <th>{t('keys.colAlgorithm')}</th>
          <th>{t('keys.colPassword')}</th>
          <th>{t('common.date')}</th>
          <th style={{ textAlign: 'right', paddingRight: '16px' }}>{t('common.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {data.map((k, i) => (
          <tr key={k.id || i}>
            <td>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                <span>{k.key_name || '-'}</span>
              </div>
            </td>
            <td><code>{k.algorithm}</code></td>
            <td>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                <span style={{ color: visibleKeys[k.id] ? 'var(--text-primary)' : 'var(--text-muted)', wordBreak: 'break-all', maxWidth: '240px' }}>
                  {visibleKeys[k.id]
                    ? (decryptedPasswords[k.id] ?? t('keys.noPassword'))
                    : '••••••••••••••'}
                </span>
                {k.encryption_password && (
                  <button
                    onClick={() => toggleVisibility(k.id, k.encryption_password)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '4px', display: 'flex', alignItems: 'center' }}
                    title={visibleKeys[k.id] ? "Sembunyikan password" : "Lihat password"}
                  >
                    {visibleKeys[k.id] ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                )}
                {!k.encryption_password && (
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontStyle: 'italic' }}>—</span>
                )}
              </div>
            </td>
            <td style={{ fontSize: '12px' }}>{new Date(k.updated_at).toLocaleString(language === 'en' ? 'en-US' : 'id-ID')}</td>
            <td style={{ textAlign: 'right', paddingRight: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '6px' }}>
                {k.file_path === 'db://vault' && (
                  <button 
                    className="btn-secondary" 
                    style={{ padding: '4px 10px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}
                    onClick={() => handleDownload(k)}
                    disabled={loadingId === k.id}
                    title={t('keys.btnDownload')}
                  >
                    <Download size={12} />
                    <span>{loadingId === k.id ? '...' : t('keys.btnDownload')}</span>
                  </button>
                )}
                <button
                  className="btn-secondary"
                  style={{ padding: '4px 10px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}
                  onClick={() => openUpdatePasswordModal(k)}
                  disabled={loadingId === k.id}
                  title={t('keys.btnUpdatePass')}
                >
                  <Edit3 size={12} />
                  <span>{t('keys.btnUpdatePass')}</span>
                </button>
                <button
                  style={{
                    padding: '4px 8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px',
                    background: 'transparent', border: '1px solid var(--danger)', color: 'var(--danger)',
                    borderRadius: '6px', cursor: 'pointer', transition: '0.15s'
                  }}
                  onMouseOver={e => e.currentTarget.style.background = 'rgba(242, 85, 90, 0.1)'}
                  onMouseOut={e => e.currentTarget.style.background = 'transparent'}
                  onClick={() => handleDelete(k)}
                  disabled={loadingId === k.id}
                  title={t('keys.btnDelete')}
                >
                  <Trash2 size={12} />
                  <span>{t('keys.btnDelete')}</span>
                </button>
              </div>
            </td>
          </tr>
        ))}
        {data.length === 0 && (
          <tr>
            <td colSpan="5" className="text-center" style={{ padding: '24px', color: 'var(--text-muted)' }}>
              {t('keys.empty')}
            </td>
          </tr>
        )}
      </tbody>
    </table>
    {totalPages > 1 && (
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--surface)', borderBottomLeftRadius: '8px', borderBottomRightRadius: '8px' }}>
        <button className="btn-secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>&larr; {t('common.prev')}</button>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{t('common.pageOf', { current: currentPage, total: totalPages })}</div>
        <button className="btn-secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>{t('common.next')} &rarr;</button>
      </div>
    )}
    </>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      {/* Update Password Modal */}
      {editModalKey && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.65)', display: 'flex', alignItems: 'center',
          justifyContent: 'center', zIndex: 1000, padding: '16px'
        }}>
          <div className="panel" style={{ width: '420px', maxWidth: '100%', display: 'flex', flexDirection: 'column' }}>
            <div className="panel-head" style={{ borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}>
                <Key size={16} style={{ color: 'var(--accent)' }} />
                <span>{t('keys.modalUpdateTitle')}</span>
              </div>
              <button
                onClick={() => setEditModalKey(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
              >
                <X size={16} />
              </button>
            </div>
            <div className="panel-body" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Target File / Key:</div>
                <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {editModalKey.key_name}
                </div>
              </div>
              <div className="field">
                <label className="field-label" style={{ fontSize: '12px', marginBottom: '6px' }}>
                  {language === 'en' ? 'New Encryption Password' : 'Password Enkripsi Baru'}
                </label>
                <div className="input-group" style={{ display: 'flex', position: 'relative' }}>
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    className="text-input"
                    placeholder={t('keys.newPassPlaceholder')}
                    value={newPasswordInput}
                    onChange={e => setNewPasswordInput(e.target.value)}
                    style={{ width: '100%', paddingRight: '36px' }}
                    autoFocus
                  />
                  <button
                    type="button"
                    className="input-icon-btn"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                  >
                    {showNewPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>
                  {language === 'en' ? 'Leave blank to remove password protection from this file.' : 'Kosongkan input jika Anda ingin menghapus password dari file ini.'}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
                <button
                  className="btn-secondary"
                  onClick={() => setEditModalKey(null)}
                  disabled={isUpdating}
                  style={{ padding: '6px 14px', fontSize: '12px' }}
                >
                  {t('common.cancel')}
                </button>
                <button
                  className="btn-primary"
                  onClick={handleSavePassword}
                  disabled={isUpdating}
                  style={{ padding: '6px 16px', fontSize: '12px' }}
                >
                  {isUpdating ? t('common.loading') : t('keys.btnSavePass')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-head" style={{ padding: '12px 16px', fontWeight: 600 }}>
          🔑 {t('keys.title')}
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {paginatedData.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              {t('keys.empty')}
            </div>
          ) : (
            renderTable(paginatedData)
          )}
        </div>
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button 
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(p => p - 1)}
          >
            {t('common.prev')}
          </button>
          <span>{t('common.pageOf', { current: currentPage, total: totalPages })}</span>
          <button 
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(p => p + 1)}
          >
            {t('common.next')}
          </button>
        </div>
      )}
    </div>
  )
}
