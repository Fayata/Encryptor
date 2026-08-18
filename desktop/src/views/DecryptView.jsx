import React, { useState, useEffect, useMemo } from 'react'
import { api } from '../lib/api'
import { Lock, Unlock, Eye, EyeOff, FolderOpen, FileText, ArrowUp, ArrowDown, Search } from 'lucide-react'
import FileViewer from '../components/FileViewer'

const STATUS_ALL       = 'all'
const STATUS_ENCRYPTED = 'encrypted'
const STATUS_DECRYPTED = 'decrypted'

export default function FileView({ user, masterKey }) {
  const [files, setFiles]             = useState([])
  const [filterStatus, setFilterStatus] = useState(STATUS_ALL)
  const [sortField, setSortField]     = useState('updated_at')
  const [sortDir, setSortDir]         = useState('desc')
  const [search, setSearch]           = useState('')

  // Decrypt modal
  const [modal, setModal]             = useState(null)
  const [inputKey, setInputKey]       = useState('')
  const [showKey, setShowKey]         = useState(false)
  const [loading, setLoading]         = useState(false)
  const [result, setResult]           = useState(null)

  // File viewer
  const [viewerPath, setViewerPath]         = useState(null)
  const [viewerB64, setViewerB64]           = useState(null)   // untuk vault: data di memory
  const [viewerFileName, setViewerFileName] = useState(null)   // nama file untuk header viewer

  // Manual decrypt modal
  const [showManual, setShowManual]   = useState(false)
  const [manualPath, setManualPath]   = useState('')

  useEffect(() => { fetchFiles() }, [])

  const fetchFiles = async () => {
    try {
      const data = await api('/api/keys')
      setFiles(Array.isArray(data) ? data : (data?.keys || []))
    } catch (err) {
      console.error(err)
    }
  }

  // ── Filtering & Sorting ──────────────────────────────────────────
  const processed = useMemo(() => {
    let list = [...files]

    // status filter
    if (filterStatus !== STATUS_ALL) {
      list = list.filter(f => (f.status || 'encrypted') === filterStatus)
    }

    // search
    const q = search.toLowerCase()
    if (q) {
      list = list.filter(f =>
        (f.key_name || '').toLowerCase().includes(q) ||
        (f.file_path || '').toLowerCase().includes(q) ||
        (f.author || '').toLowerCase().includes(q) ||
        (f.algorithm || '').toLowerCase().includes(q)
      )
    }

    // sort
    list.sort((a, b) => {
      let av = a[sortField] || ''
      let bv = b[sortField] || ''
      if (sortField === 'updated_at' || sortField === 'created_at') {
        av = new Date(av)
        bv = new Date(bv)
      } else {
        av = av.toString().toLowerCase()
        bv = bv.toString().toLowerCase()
      }
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })

    return list
  }, [files, filterStatus, sortField, sortDir, search])

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <ArrowUp size={11} style={{ opacity: 0.25 }} />
    return sortDir === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />
  }

  // ── Decrypt Actions ──────────────────────────────────────────────
  const openDecryptModal = (f) => {
    if ((f.status || 'encrypted') === 'decrypted') return
    setInputKey('')
    setShowKey(false)
    setResult(null)
    setModal(f)
  }

  const handleOpenDecrypted = async (f) => {
    if (f.file_path === 'db://vault') {
      // Buka vault in-memory tanpa password prompt lagi karena udah didecrypt (status updated)
      setLoading(true)
      try {
        const token = localStorage.getItem('api_token')
        const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080'
        const res = await fetch(`${API_URL}/api/vault/download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Token': token,
            'X-Master-Key': masterKey
          },
          body: JSON.stringify({ key_id: f.id })
        })
        if (!res.ok) {
          alert('Gagal mengambil file dari vault')
          return
        }
        let filename = f.key_name || 'file'
        const disposition = res.headers.get('content-disposition')
        if (disposition) {
          const match = /filename="([^"]+)"/.exec(disposition)
          if (match && match[1]) filename = match[1]
        }
        const blob = await res.blob()
        const reader = new FileReader()
        reader.onload = () => {
          const base64 = reader.result.split(',')[1]
          setViewerB64(base64)
          setViewerFileName(filename)
          setLoading(false)
        }
        reader.readAsDataURL(blob)
      } catch (err) {
        alert(err.message)
        setLoading(false)
      }
    } else {
      // Local file -> viewerPath
      setViewerPath(f.file_path)
    }
  }

  const handleConfirmDecrypt = async () => {
    setLoading(true)
    setResult(null)

    const isVaultFile = modal.file_path === 'db://vault'

    try {
      if (isVaultFile) {
        // Vault file: dekripsi server-side pakai masterKey → terima bytes → tampilkan di FileViewer
        // File TIDAK pernah ditulis ke disk
        const token = localStorage.getItem('api_token')
        const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080'
        const res = await fetch(`${API_URL}/api/vault/download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Token': token,
            'X-Master-Key': masterKey
          },
          body: JSON.stringify({ key_id: modal.id })
        })

        if (!res.ok) {
          const errText = await res.text()
          setResult({ success: false, error: errText || 'Gagal mendekripsi file dari vault.' })
          return
        }

        // Ambil nama file dari header
        let filename = modal.key_name || 'file'
        const disposition = res.headers.get('content-disposition')
        if (disposition) {
          const match = /filename="([^"]+)"/.exec(disposition)
          if (match && match[1]) filename = match[1]
        }

        // Konversi blob → base64 di memory, lalu buka langsung di FileViewer
        const blob = await res.blob()
        const reader = new FileReader()
        reader.onload = () => {
          // result dari FileReader adalah "data:mime/type;base64,xxxx" — ambil bagian base64-nya saja
          const base64 = reader.result.split(',')[1]
          setViewerB64(base64)
          setViewerFileName(filename)
          setModal(null) // tutup modal dekripsi
          setLoading(false)
        }
        reader.readAsDataURL(blob)

      } else {
        // Local file: wajib pakai password
        if (!inputKey.trim()) { alert('Masukkan key/password terlebih dahulu.'); setLoading(false); return }

        const res = await api('/api/local/decrypt', {
          method: 'POST',
          headers: { 'X-Master-Key': masterKey },
          body: JSON.stringify({ folder_path: modal.file_path, password: inputKey })
        })
        if (res.failed && res.failed > 0 && (!res.success || res.success === 0)) {
          setResult({ success: false, error: (res.errors || ['Key salah atau file rusak.']).join(', ') })
        } else {
          setResult({ success: true, message: `Berhasil! ${res.success || 1} file berhasil didekripsi.` })
          fetchFiles()
        }
      }
    } catch (err) {
      setResult({ success: false, error: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleManualDecrypt = async () => {
    if (!manualPath.trim()) { alert('Masukkan path file/folder.'); return }
    if (!inputKey.trim()) { alert('Masukkan key/password terlebih dahulu.'); return }
    setLoading(true)
    setResult(null)
    try {
      const res = await api('/api/local/decrypt', {
        method: 'POST',
        body: JSON.stringify({ folder_path: manualPath, password: inputKey })
      })
      if (res.failed && res.failed > 0 && (!res.success || res.success === 0)) {
        setResult({ success: false, error: (res.errors || ['Key salah.']).join(', ') })
      } else {
        setResult({ success: true, message: `Berhasil! ${res.success || 1} file berhasil didekripsi.` })
        fetchFiles()
      }
    } catch (err) {
      setResult({ success: false, error: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleBrowseFolder = async (setter) => {
    if (window.electronAPI?.selectFolder) {
      const p = await window.electronAPI.selectFolder()
      if (p) setter(p)
    }
  }

  const handleBrowseFile = async (setter) => {
    if (window.electronAPI?.selectFile) {
      const p = await window.electronAPI.selectFile()
      if (p) setter(p)
    }
  }

  const closeModal = () => {
    setModal(null)
    setShowManual(false)
    setInputKey('')
    setShowKey(false)
    setResult(null)
    setManualPath('')
  }

  // counts
  const encryptedCount = files.filter(f => (f.status || 'encrypted') === 'encrypted').length
  const decryptedCount = files.filter(f => f.status === 'decrypted').length

  return (
    <div style={{ padding: '0', height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>

      {/* ── Toolbar ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: '1', minWidth: '200px' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            type="text"
            className="text-input"
            placeholder="Cari nama, path, author..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: '32px', width: '100%' }}
          />
        </div>

        {/* Status filter pills */}
        <div className="segmented" style={{ flexShrink: 0 }}>
          {[
            { key: STATUS_ALL,       label: `Semua (${files.length})` },
            { key: STATUS_ENCRYPTED, label: `Terenkripsi (${encryptedCount})` },
            { key: STATUS_DECRYPTED, label: `Terdekripsi (${decryptedCount})` },
          ].map(({ key, label }) => (
            <button
              key={key}
              className={filterStatus === key ? 'active' : ''}
              onClick={() => setFilterStatus(key)}
            >
              {label}
            </button>
          ))}
        </div>

        <button className="btn-secondary" style={{ flexShrink: 0 }} onClick={() => {
          setManualPath('')
          setInputKey('')
          setShowKey(false)
          setResult(null)
          setShowManual(true)
        }}>
          Manual Decrypt
        </button>
      </div>

      {/* ── Table ── */}
      <div className="panel" style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => toggleSort('key_name')}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>Nama File <SortIcon field="key_name" /></span>
              </th>
              <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => toggleSort('author')}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>Author <SortIcon field="author" /></span>
              </th>
              <th>Algorithm</th>
              <th>Status</th>
              <th style={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => toggleSort('updated_at')}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>Tanggal <SortIcon field="updated_at" /></span>
              </th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {processed.map((f, i) => {
              const isDecrypted = f.status === 'decrypted'
              return (
                <tr key={f.id || i} style={{ opacity: isDecrypted ? 0.6 : 1 }}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {isDecrypted
                        ? <Unlock size={13} style={{ color: 'var(--success)', flexShrink: 0 }} />
                        : <Lock size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                      }
                      <div>
                        <div style={{ fontWeight: 500 }}>{f.key_name || '-'}</div>
                      </div>
                    </div>
                  </td>
                  <td style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                    {f.author || user?.username || '-'}
                  </td>
                  <td><code style={{ fontSize: '11px' }}>{f.algorithm}</code></td>
                  <td>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: '4px',
                      padding: '2px 8px', borderRadius: '99px', fontSize: '11px', fontWeight: 500,
                      background: isDecrypted ? 'var(--success-tint)' : 'var(--accent-tint)',
                      color: isDecrypted ? 'var(--success)' : 'var(--accent)'
                    }}>
                      {isDecrypted ? '✓ Terdekripsi' : '🔒 Terenkripsi'}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {new Date(f.updated_at).toLocaleDateString('id-ID', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' })}
                  </td>
                  <td>
                    {!isDecrypted ? (
                      <button
                        className="btn-primary"
                        style={{ padding: '4px 12px', fontSize: '12px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => openDecryptModal(f)}
                      >
                        <Unlock size={12} /> Decrypt
                      </button>
                    ) : (
                      <button
                        className="btn-secondary"
                        style={{ padding: '4px 12px', fontSize: '12px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => handleOpenDecrypted(f)}
                      >
                        <FileText size={12} /> Buka
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
            {processed.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  {files.length === 0 ? 'Belum ada file di vault. Enkripsi file terlebih dahulu.' : 'Tidak ada file yang cocok dengan filter.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── MODAL: Decrypt dari Vault ── */}
      {modal && (
        <div className="viewer-overlay">
          <div className="viewer-modal" style={{ width: '460px', height: 'auto', padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <Lock size={20} style={{ color: 'var(--accent)' }} />
              <h3 style={{ margin: 0 }}>Masukkan Key untuk Dekripsi</h3>
            </div>

            <div style={{ background: 'var(--surface-2)', borderRadius: '8px', padding: '12px 16px', marginBottom: '20px' }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>{modal.key_name}</div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Author: <strong style={{ color: 'var(--text-secondary)' }}>{modal.author || user?.username}</strong>
                &nbsp;·&nbsp; Algorithm: <code>{modal.algorithm}</code>
              </div>
            </div>

            <div className="field">
              <label className="field-label">Key / Password</label>
              <div className="input-group">
                <input
                  type={showKey ? 'text' : 'password'}
                  className="text-input"
                  placeholder="Masukkan key yang diberikan author..."
                  value={inputKey}
                  onChange={e => setInputKey(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleConfirmDecrypt()}
                  autoFocus
                />
                <button className="input-icon-btn" onClick={() => setShowKey(!showKey)}>
                  {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              <div className="field-hint">Key ini diberikan oleh author yang mengenkripsi file.</div>
            </div>

            {result && (
              <div style={{
                marginTop: '12px', padding: '10px 14px', borderRadius: '6px',
                background: result.success ? 'var(--success-tint)' : 'rgba(242,85,90,0.12)',
                color: result.success ? 'var(--success)' : 'var(--danger)', fontSize: '13px'
              }}>
                {result.success ? result.message : `❌ ${result.error}`}
              </div>
            )}

            <div className="actions-row" style={{ marginTop: '24px', justifyContent: 'flex-end' }}>
              <button className="btn-secondary" onClick={closeModal}>Tutup</button>
              {!result?.success && (
                <button className="btn-primary" onClick={handleConfirmDecrypt} disabled={loading}>
                  {loading ? 'Mendekripsi...' : 'Dekripsi Sekarang'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: Manual Decrypt ── */}
      {showManual && (
        <div className="viewer-overlay">
          <div className="viewer-modal" style={{ width: '500px', height: 'auto', padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <Unlock size={20} style={{ color: 'var(--accent)' }} />
              <h3 style={{ margin: 0 }}>Manual Decrypt</h3>
            </div>

            <div className="field">
              <label className="field-label">Path File / Folder</label>
              <div className="path-row">
                <input
                  type="text"
                  className="path-input"
                  placeholder="C:\Users\...\file.pdf.enc atau folder"
                  value={manualPath}
                  onChange={e => setManualPath(e.target.value)}
                />
                <button className="btn-secondary" title="Pilih Folder" onClick={() => handleBrowseFolder(setManualPath)}>
                  <FolderOpen size={14} />
                </button>
                <button className="btn-secondary" title="Pilih File" onClick={() => handleBrowseFile(setManualPath)}>
                  <FileText size={14} />
                </button>
              </div>
              <div className="field-hint">Pilih file .enc atau folder yang berisi file .enc</div>
            </div>

            <div className="field">
              <label className="field-label">Key / Password</label>
              <div className="input-group">
                <input
                  type={showKey ? 'text' : 'password'}
                  className="text-input"
                  placeholder="Masukkan key yang diberikan author..."
                  value={inputKey}
                  onChange={e => setInputKey(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleManualDecrypt()}
                />
                <button className="input-icon-btn" onClick={() => setShowKey(!showKey)}>
                  {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {result && (
              <div style={{
                marginTop: '12px', padding: '10px 14px', borderRadius: '6px',
                background: result.success ? 'var(--success-tint)' : 'rgba(242,85,90,0.12)',
                color: result.success ? 'var(--success)' : 'var(--danger)', fontSize: '13px'
              }}>
                {result.success ? result.message : `❌ ${result.error}`}
              </div>
            )}

            <div className="actions-row" style={{ marginTop: '24px', justifyContent: 'flex-end' }}>
              <button className="btn-secondary" onClick={closeModal}>Tutup</button>
              {!result?.success && (
                <button className="btn-primary" onClick={handleManualDecrypt} disabled={loading}>
                  {loading ? 'Mendekripsi...' : 'Dekripsi Sekarang'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
      {/* ── FILE VIEWER ── local file */}
      {viewerPath && <FileViewer filePath={viewerPath} onClose={() => setViewerPath(null)} />}

      {/* ── FILE VIEWER ── vault file (dari memory, tidak menyentuh disk) */}
      {viewerB64 && (
        <FileViewer
          b64Data={viewerB64}
          fileName={viewerFileName}
          onClose={() => { setViewerB64(null); setViewerFileName(null) }}
        />
      )}
    </div>
  )
}
