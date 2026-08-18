import React, { useState, useEffect, useCallback } from 'react'
import * as XLSX from 'xlsx'
import mammoth from 'mammoth'
import DOMPurify from 'dompurify'
import { X, FileText, Table, Image, File, Loader, Shield } from 'lucide-react'

// ── Detect file type ─────────────────────────────────────────────
function detectType(filePath) {
  const ext = (filePath.split('.').pop() || '').toLowerCase()
  if (['txt','md','json','xml','log','ini','yaml','yml','toml','sh','bat','ps1',
       'py','js','ts','jsx','tsx','go','java','c','cpp','h','rs','rb','php',
       'html','css','scss','sql','env'].includes(ext)) return { type: 'text', ext }
  if (ext === 'csv') return { type: 'excel', ext }
  if (ext === 'pdf') return { type: 'pdf', ext }
  if (['png','jpg','jpeg','gif','webp','bmp','svg','ico'].includes(ext)) return { type: 'image', ext }
  if (['xlsx','xls','ods'].includes(ext)) return { type: 'excel', ext }
  if (['docx','doc'].includes(ext)) return { type: 'word', ext }
  if (['pptx','ppt'].includes(ext)) return { type: 'ppt', ext }
  return { type: 'unknown', ext }
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

// ── Sub-viewers ──────────────────────────────────────────────────
function TextViewer({ b64 }) {
  const text = atob(b64)
  return (
    <pre style={{
      margin: 0, padding: '20px', overflowY: 'auto', flex: 1,
      fontFamily: 'var(--font-mono)', fontSize: '13px', lineHeight: '1.7',
      color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      background: 'var(--console-bg)',
    }}>{text}</pre>
  )
}

function ImageViewer({ b64, ext }) {
  const mimeMap = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp', bmp:'image/bmp', svg:'image/svg+xml', ico:'image/x-icon' }
  const mime = mimeMap[ext] || 'image/png'
  return (
    <div style={{ flex: 1, overflow: 'auto', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px', background: 'var(--console-bg)' }}>
      <img
        src={`data:${mime};base64,${b64}`}
        alt="Preview"
        style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '4px' }}
      />
    </div>
  )
}

function PDFViewer({ b64 }) {
  const [blobUrl, setBlobUrl] = useState(null)

  useEffect(() => {
    if (!b64) return
    const buf  = base64ToArrayBuffer(b64)
    const blob = new Blob([buf], { type: 'application/pdf' })
    const url  = URL.createObjectURL(blob)
    setBlobUrl(url)
    return () => URL.revokeObjectURL(url)
  }, [b64])

  if (!blobUrl) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px', color: 'var(--text-muted)' }}>
      <Loader size={18} /> Memuat PDF...
    </div>
  )

  return (
    <iframe
      src={blobUrl}
      style={{ flex: 1, border: 'none', width: '100%', minHeight: '500px' }}
      title="PDF Viewer"
    />
  )
}

function ExcelViewer({ b64, ext }) {
  const [sheets, setSheets]     = useState({})
  const [activeSheet, setActive] = useState('')
  const [error, setError]       = useState(null)

  useEffect(() => {
    try {
      let wb
      if (ext === 'csv') {
        wb = XLSX.read(atob(b64), { type: 'string' })
      } else {
        wb = XLSX.read(base64ToArrayBuffer(b64), { type: 'array' })
      }
      const result = {}
      wb.SheetNames.forEach(n => { result[n] = XLSX.utils.sheet_to_json(wb.Sheets[n], { header: 1 }) })
      setSheets(result)
      setActive(wb.SheetNames[0] || '')
    } catch (e) { setError(e.message) }
  }, [b64, ext])

  if (error) return <div style={{ padding: '24px', color: 'var(--danger)' }}>Error membaca file: {error}</div>
  if (!activeSheet) return <div style={{ padding: '24px', color: 'var(--text-muted)' }}>File kosong.</div>

  const rows    = sheets[activeSheet] || []
  const headers = rows[0] || []
  const data    = rows.slice(1)

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {Object.keys(sheets).length > 1 && (
        <div style={{ display: 'flex', gap: '4px', padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface-2)', flexShrink: 0 }}>
          {Object.keys(sheets).map(name => (
            <button key={name} onClick={() => setActive(name)} style={{
              padding: '4px 12px', borderRadius: '4px', fontSize: '12px',
              border: '1px solid var(--border)', cursor: 'pointer',
              background: activeSheet === name ? 'var(--accent)' : 'var(--surface)',
              color: activeSheet === name ? '#fff' : 'var(--text-secondary)',
            }}>{name}</button>
          ))}
        </div>
      )}
      <div style={{ flex: 1, overflow: 'auto', padding: '8px' }}>
        <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: '13px', whiteSpace: 'nowrap' }}>
          <thead>
            <tr>
              {headers.map((h, i) => (
                <th key={i} style={{ padding: '6px 12px', background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontWeight: 600, position: 'sticky', top: 0, zIndex: 1 }}>
                  {h != null ? String(h) : ''}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, ri) => (
              <tr key={ri} style={{ background: ri % 2 === 0 ? 'transparent' : 'var(--surface-2)' }}>
                {headers.map((_, ci) => (
                  <td key={ci} style={{ padding: '5px 12px', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                    {row[ci] != null ? String(row[ci]) : ''}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {data.length === 0 && <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>Sheet kosong.</div>}
      </div>
    </div>
  )
}

function WordViewer({ b64 }) {
  const [html, setHtml]   = useState('')
  const [error, setError] = useState(null)

  useEffect(() => {
    mammoth.convertToHtml({ arrayBuffer: base64ToArrayBuffer(b64) })
      .then(r => setHtml(DOMPurify.sanitize(r.value)))
      .catch(e => setError(e.message))
  }, [b64])

  if (error) return <div style={{ padding: '24px', color: 'var(--danger)' }}>Error membaca dokumen: {error}</div>
  if (!html)  return <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', color: 'var(--text-muted)' }}><Loader size={16} /> Memuat dokumen...</div>

  return (
    <div style={{ flex: 1, overflow: 'auto', background: '#e0e0e0', padding: '32px' }}>
      <div
        className="docx-viewer"
        style={{ maxWidth: '800px', margin: '0 auto', padding: '48px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  )
}

// For unsupported / PPT: no "open with system" — file is protected
function ProtectedUnsupportedViewer({ ext }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '16px', color: 'var(--text-muted)', padding: '32px', textAlign: 'center' }}>
      <Shield size={48} style={{ color: 'var(--accent)', opacity: 0.6 }} />
      <div>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
          Format <code>.{ext}</code> tidak dapat ditampilkan
        </div>
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '360px' }}>
          File ini dilindungi dan hanya dapat dibuka dalam aplikasi Faycryptor.
          Format ini belum didukung oleh viewer bawaan. Hubungi author untuk mendapatkan format yang didukung.
        </div>
      </div>
    </div>
  )
}

// ── Main FileViewer Modal ────────────────────────────────────────
// Props:
//   filePath  — path file lokal (baca via electronAPI.readFile)
//   b64Data   — base64 string langsung dari memory (untuk vault, tidak menyentuh disk)
//   fileName  — nama file untuk ditampilkan di header (wajib jika pakai b64Data)
//   onClose   — callback tutup modal
export default function FileViewer({ filePath, b64Data, fileName: fileNameProp, onClose }) {
  const [b64, setB64]         = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  // Jika b64Data diberikan langsung (vault mode), pakai itu tanpa baca disk
  const resolvedName = fileNameProp || (filePath ? filePath.split(/[\\/]/).pop() : 'file')
  const { type, ext } = detectType(resolvedName)

  useEffect(() => {
    if (b64Data) {
      // Data sudah ada di memory — langsung pakai, tidak perlu baca disk
      setB64(b64Data)
      setLoading(false)
      return
    }
    if (!filePath) {
      setError('Tidak ada file yang diberikan.')
      setLoading(false)
      return
    }
    if (!window.electronAPI?.readFile) {
      setError('readFile API tidak tersedia.')
      setLoading(false)
      return
    }
    window.electronAPI.readFile(filePath)
      .then(data => { setB64(data); setLoading(false) })
      .catch(e  => { setError(e.message); setLoading(false) })
  }, [filePath, b64Data])

  const typeIcon = {
    text: <FileText size={14} />, pdf: <FileText size={14} />,
    image: <Image size={14} />, excel: <Table size={14} />,
    word: <FileText size={14} />, ppt: <File size={14} />, unknown: <File size={14} />
  }

  return (
    <div className="viewer-overlay" style={{ zIndex: 1000 }}>
      <div style={{
        background: 'var(--surface)', borderRadius: '12px',
        display: 'flex', flexDirection: 'column',
        width: '90vw', height: '88vh', maxWidth: '1100px',
        border: '1px solid var(--border)', overflow: 'hidden',
        boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
      }}>
        {/* ── Header ── */}
        <div style={{
          display: 'flex', alignItems: 'center', padding: '12px 16px',
          borderBottom: '1px solid var(--border)', background: 'var(--surface-2)',
          flexShrink: 0, gap: '10px',
        }}>
          <div style={{ color: 'var(--accent)' }}>{typeIcon[type]}</div>
          <span style={{ fontWeight: 600, fontSize: '14px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {resolvedName}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '3px 10px', borderRadius: '99px', background: 'var(--accent-tint)', border: '1px solid var(--border)' }}>
            <Shield size={11} style={{ color: 'var(--accent)' }} />
            <span style={{ fontSize: '11px', color: 'var(--accent)', fontWeight: 500 }}>Protected</span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', padding: '2px 8px', background: 'var(--surface)', borderRadius: '99px', border: '1px solid var(--border)' }}>
            .{ext}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', padding: '4px' }}>
            <X size={18} />
          </button>
        </div>

        {/* ── Content ── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {loading && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px', color: 'var(--text-muted)' }}>
              <Loader size={18} /> Memuat file...
            </div>
          )}
          {!loading && error && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '12px', color: 'var(--danger)', padding: '32px', textAlign: 'center' }}>
              <Shield size={36} style={{ opacity: 0.5 }} />
              <div style={{ fontWeight: 600 }}>Gagal membuka file</div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{error}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Pastikan file sudah terdekripsi dengan benar.</div>
            </div>
          )}
          {!loading && !error && b64 && (
            <>
              {type === 'text'    && <TextViewer b64={b64} />}
              {type === 'image'   && <ImageViewer b64={b64} ext={ext} />}
              {type === 'pdf'     && <PDFViewer b64={b64} />}
              {type === 'excel'   && <ExcelViewer b64={b64} ext={ext} />}
              {type === 'word'    && <WordViewer b64={b64} />}
              {(type === 'ppt' || type === 'unknown') && <ProtectedUnsupportedViewer ext={ext} />}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
