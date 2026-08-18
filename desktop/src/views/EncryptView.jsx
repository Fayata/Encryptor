import React, { useState } from 'react'
import { api } from '../lib/api'
import { Eye, EyeOff } from 'lucide-react'

const ALGORITHMS = [
  { id: 'aes-gcm', label: 'AES-256-GCM' },
  { id: 'aes-cbc', label: 'AES-256-CBC' },
  { id: 'chacha20', label: 'XChaCha20-Poly1305' },
]

export default function EncryptView({ masterKey }) {
  const [tab, setTab] = useState('vault') // 'local' or 'vault'
  const [folderPath, setFolderPath] = useState('')
  const [selectedAlgo, setSelectedAlgo] = useState('aes-gcm')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [syncToVault, setSyncToVault] = useState(true)
  const [secureWipe, setSecureWipe] = useState(false)
  const [deleteOriginal, setDeleteOriginal] = useState(false)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)

  const handleBrowse = async () => {
    if (window.electronAPI?.selectFolder) {
      const path = await window.electronAPI.selectFolder()
      if (path) setFolderPath(path)
    } else {
      alert('Browse is only supported in the Desktop App')
    }
  }

  const handleEncrypt = async () => {
    if (!folderPath) return
    setLoading(true)
    setLogs(prev => [...prev, `Starting ${tab === 'vault' ? 'Vault Upload' : 'Local Encryption'} for ${folderPath}...`])
    
    try {
      const endpoint = tab === 'vault' ? '/api/vault/upload' : '/api/local/encrypt'
      const payload = {
        folder_path: folderPath,
        file_path: folderPath,
        algorithm: selectedAlgo,
        password
      }
      
      if (tab === 'local') {
        payload.sync_to_vault = syncToVault
        payload.secure_wipe = secureWipe
      }

      const data = await api(endpoint, {
        method: 'POST',
        headers: { 'X-Master-Key': masterKey },
        body: JSON.stringify(payload)
      })

      alert(`Berhasil diamankan!`)
      setFolderPath('')
      setPassword('')
      setLogs(prev => [...prev, `Success.`])
    } catch (err) {
      setLogs(prev => [...prev, `Error: ${err.message}`])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '24px', alignItems: 'start' }}>
      <div className="panel">
        <div className="panel-head" style={{ padding: '12px 16px', fontWeight: 600 }}>
          ☁️ Cloud Vault Upload
        </div>
        <div className="panel-body">
          {tab === 'vault' && (
            <div style={{ marginBottom: '16px', fontSize: '13px', color: 'var(--text-muted)' }}>
              File akan disalin dan dienkripsi ke dalam Cloud Vault untuk keperluan sharing. File asli Anda di komputer tidak akan dihapus atau dimodifikasi.
            </div>
          )}
          
          <div className="field">
            <label className="field-label">{tab === 'vault' ? 'Pilih File untuk Diupload' : 'Target Folder Path'}</label>
            <div className="path-row">
              <input 
                type="text" 
                className="path-input" 
                value={folderPath}
                onChange={e => setFolderPath(e.target.value)}
                placeholder="C:\Users\Documents\Secret"
              />
              {tab === 'local' && <button className="btn-secondary" onClick={handleBrowse}>Folder...</button>}
              <button className="btn-secondary" onClick={async () => {
                if (window.electronAPI?.selectFile) {
                  const path = await window.electronAPI.selectFile()
                  if (path) setFolderPath(path)
                }
              }}>File...</button>
            </div>
          </div>

          <div className="field">
            <label className="field-label">Algorithm</label>
            <div className="segmented" style={{ flexWrap: 'wrap' }}>
              {ALGORITHMS.map(algo => (
                <button 
                  key={algo.id}
                  className={selectedAlgo === algo.id ? 'active' : ''}
                  onClick={() => setSelectedAlgo(algo.id)}
                >
                  {algo.label}
                </button>
              ))}
            </div>
          </div>

          <div className="field">
            <label className="field-label">Encryption Password (Optional)</label>
            <div className="input-group">
              <input 
                type={showPassword ? 'text' : 'password'} 
                className="text-input" 
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
              <button className="input-icon-btn" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {tab === 'local' && (
            <>
              <div className="field">
                <label className="field-label">Sync Kunci ke Vault</label>
                <div className="toggle-row">
                  <div className="switch">
                    <input type="checkbox" id="sync" checked={syncToVault} onChange={e => setSyncToVault(e.target.checked)} />
                    <label htmlFor="sync"></label>
                  </div>
                </div>
              </div>

              <div className="field">
                <label className="field-label">Secure Wipe (Hapus Permanen)</label>
                <div className="toggle-row">
                  <div className="switch">
                    <input type="checkbox" id="wipe" checked={secureWipe} onChange={e => setSecureWipe(e.target.checked)} />
                    <label htmlFor="wipe"></label>
                  </div>
                </div>
              </div>

              <div className="toggle-row">
                <div className="toggle-text">
                  <strong>Hapus file asli</strong>
                </div>
                <div className="switch">
                  <input type="checkbox" id="delete-toggle" checked={deleteOriginal} onChange={e => setDeleteOriginal(e.target.checked)} />
                  <label htmlFor="delete-toggle"></label>
                </div>
              </div>
            </>
          )}

          <div className="actions-row">
            <button className="btn-secondary">Generate key</button>
            <button className="btn-primary" onClick={handleEncrypt} disabled={loading}>
              {loading ? 'Processing...' : (tab === 'vault' ? 'Upload to Vault' : 'Encrypt')}
            </button>
          </div>
        </div>
      </div>

      <div className="console">
        <div className="console-head">
          <span>Process Log</span>
        </div>
        <div className="console-body">
          <div className="log-feed">
            {logs.map((log, i) => (
              <div key={i} className="log-row">{log}</div>
            ))}
            {logs.length === 0 && <div className="log-row text-muted">Ready...</div>}
          </div>
        </div>
      </div>
    </div>
  )
}
