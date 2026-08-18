import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'
import { Key, Eye, EyeOff } from 'lucide-react'

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
  const [keys, setKeys] = useState([])
  const [visibleKeys, setVisibleKeys] = useState({})
  const [decryptedPasswords, setDecryptedPasswords] = useState({}) // id -> plaintext password
  const [tab, setTab] = useState('vault') // always vault
  const [loadingId, setLoadingId] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)

  useEffect(() => {
    setCurrentPage(1)
  }, [tab])

  useEffect(() => {
    fetchKeys()
  }, [])

  const fetchKeys = () => {
    api('/api/keys')
      .then(data => setKeys(Array.isArray(data) ? data : (data?.keys || [])))
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
      // We must use raw fetch because our lib/api parses JSON, but download returns a file stream
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

      // Extract filename from header
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
          <th>Nama</th>
          <th>Algorithm</th>
          <th>Encryption Password</th>
          <th>Updated</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody>
        {data.map((k, i) => (
          <tr key={i}>
            <td>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                <span>{k.key_name || '-'}</span>
              </div>
            </td>
            <td><code>{k.algorithm}</code></td>
            <td>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                <span style={{ color: visibleKeys[k.id] ? 'var(--text-primary)' : 'var(--text-muted)', wordBreak: 'break-all', maxWidth: '300px' }}>
                  {visibleKeys[k.id]
                    ? (decryptedPasswords[k.id] ?? '(tidak ada password)')
                    : '••••••••••••••'}
                </span>
                {k.encryption_password && (
                  <button
                    onClick={() => toggleVisibility(k.id, k.encryption_password)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '4px', display: 'flex', alignItems: 'center' }}
                  >
                    {visibleKeys[k.id] ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                )}
                {!k.encryption_password && (
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontStyle: 'italic' }}>—</span>
                )}
              </div>
            </td>
            <td style={{ fontSize: '12px' }}>{new Date(k.updated_at).toLocaleString()}</td>
            <td>
              {k.file_path === 'db://vault' && (
                <button 
                  className="btn-secondary" 
                  style={{ padding: '4px 12px', fontSize: '12px' }}
                  onClick={() => handleDownload(k)}
                  disabled={loadingId === k.id}
                >
                  {loadingId === k.id ? 'Mengunduh...' : 'Download'}
                </button>
              )}
            </td>
          </tr>
        ))}
        {data.length === 0 && (
          <tr>
            <td colSpan="5" className="text-center" style={{ padding: '24px', color: 'var(--text-muted)' }}>
              Belum ada data tersimpan.
            </td>
          </tr>
        )}
      </tbody>
    </table>
    {totalPages > 1 && (
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--surface)', borderBottomLeftRadius: '8px', borderBottomRightRadius: '8px' }}>
        <button className="btn-secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>&larr; Prev</button>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Halaman {currentPage} dari {totalPages}</div>
        <button className="btn-secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>Next &rarr;</button>
      </div>
    )}
    </>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      <div className="panel">
        <div className="panel-head" style={{ padding: '12px 16px', fontWeight: 600 }}>
          ☁️ Web Vault Keys
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {paginatedData.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Tidak ada file/key ditemukan.
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
            Prev
          </button>
          <span>Page {currentPage} of {totalPages}</span>
          <button 
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(p => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
