import React, { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../lib/api'
import { Users, UserPlus, Check, X, Send, Trash2, Search, Loader } from 'lucide-react'
import ShareModal from '../components/ShareModal'
import { useTranslation } from '../lib/i18n'

export default function ConnectionsView({ user, masterKey }) {
  const { t, language } = useTranslation()
  const [connections, setConnections] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [isSearching, setIsSearching] = useState(false)
  const [hasSearched, setHasSearched] = useState(false)
  const [sendingRequestTo, setSendingRequestTo] = useState(null)
  const [message, setMessage] = useState({ text: '', type: '' })
  const [shareRecipient, setShareRecipient] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)

  const searchTimeoutRef = useRef(null)

  const fetchConnections = () => {
    api('/api/connections')
      .then(data => setConnections(data || []))
      .catch(err => console.error(err))
  }

  useEffect(() => {
    fetchConnections()
  }, [])

  const executeSearch = async (query) => {
    const q = query.trim()
    if (!q) {
      setSearchResults([])
      setIsSearching(false)
      setHasSearched(false)
      return
    }

    setIsSearching(true)
    setHasSearched(true)
    try {
      const data = await api(`/api/users/search?q=${encodeURIComponent(q)}`)
      setSearchResults(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Search error:', err)
      setSearchResults([])
    } finally {
      setIsSearching(false)
    }
  }

  const handleInputChange = (e) => {
    const val = e.target.value
    setSearchQuery(val)
    setMessage({ text: '', type: '' })

    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }

    if (!val.trim()) {
      setSearchResults([])
      setHasSearched(false)
      setIsSearching(false)
      return
    }

    setIsSearching(true)
    searchTimeoutRef.current = setTimeout(() => {
      executeSearch(val)
    }, 250)
  }

  const handleSearchSubmit = (e) => {
    e.preventDefault()
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    executeSearch(searchQuery)
  }

  const handleSendRequest = async (targetUsername) => {
    setSendingRequestTo(targetUsername)
    setMessage({ text: '', type: '' })
    try {
      await api('/api/connections/request', {
        method: 'POST',
        body: JSON.stringify({ username: targetUsername })
      })
      setMessage({ text: `Permintaan koneksi berhasil dikirim ke ${targetUsername}.`, type: 'success' })
      
      // Update local status in search results
      setSearchResults(prev => prev.map(u => 
        u.username === targetUsername ? { ...u, connection_status: 'pending_sent' } : u
      ))
      fetchConnections()
    } catch (err) {
      setMessage({ text: err.message || 'Gagal mengirim permintaan', type: 'error' })
    } finally {
      setSendingRequestTo(null)
    }
  }

  const handleAccept = async (connId) => {
    try {
      await api('/api/connections/accept', {
        method: 'POST',
        body: JSON.stringify({ connection_id: connId })
      })
      fetchConnections()
      // Refresh search results if active
      if (searchQuery.trim()) {
        executeSearch(searchQuery)
      }
    } catch (err) {
      alert(err.message || 'Gagal menerima koneksi')
    }
  }

  const handleReject = async (connId) => {
    try {
      await api('/api/connections/reject', {
        method: 'POST',
        body: JSON.stringify({ connection_id: connId })
      })
      fetchConnections()
      if (searchQuery.trim()) {
        executeSearch(searchQuery)
      }
    } catch (err) {
      alert(err.message || 'Gagal menolak koneksi')
    }
  }

  const handleRemoveConnection = async (connId, name) => {
    if (!window.confirm(`Apakah Anda yakin ingin memutuskan koneksi dengan ${name}?`)) return
    try {
      await api('/api/connections/remove', {
        method: 'POST',
        body: JSON.stringify({ connection_id: connId })
      })
      fetchConnections()
      if (searchQuery.trim()) {
        executeSearch(searchQuery)
      }
    } catch (err) {
      alert(err.message || 'Gagal menghapus koneksi')
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
          masterKey={masterKey}
          onClose={() => setShareRecipient(null)} 
        />
      )}
      <div className="panel">
        <div className="panel-head" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Search size={16} style={{ color: 'var(--accent)' }} />
          <span>{t('workspace.searchFriends')}</span>
        </div>
        <div className="panel-body">
          <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px' }}>
            <div style={{ position: 'relative', flex: 1, display: 'flex', alignItems: 'center' }}>
              <input 
                type="text" 
                className="text-input" 
                placeholder={t('workspace.searchPlaceholder')} 
                value={searchQuery} 
                onChange={handleInputChange}
                style={{ width: '100%', paddingRight: isSearching ? '36px' : '12px' }}
              />
              {isSearching && (
                <Loader size={16} className="spin" style={{ position: 'absolute', right: '12px', color: 'var(--text-muted)' }} />
              )}
            </div>
            <button type="submit" className="btn-primary" disabled={isSearching || !searchQuery.trim()} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <Search size={15} />
              <span>{t('common.search')}</span>
            </button>
          </form>

          {message.text && (
            <div style={{ marginTop: '12px', fontSize: '13px', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
              {message.text}
            </div>
          )}

          {/* Live Search Results List */}
          {hasSearched && (
            <div style={{ marginTop: '16px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                {t('workspace.searchResults')} ({searchResults.length})
              </div>

              {searchResults.length === 0 && !isSearching && (
                <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--surface-2)', borderRadius: '8px' }}>
                  {t('workspace.noUsersFound', { query: searchQuery })}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {searchResults.map(item => {
                  return (
                    <div 
                      key={item.id}
                      style={{
                        padding: '12px 16px',
                        background: 'var(--surface-2)',
                        borderRadius: '8px',
                        border: '1px solid var(--border)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{ width: '34px', height: '34px', borderRadius: '50%', background: 'var(--accent-tint)', color: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
                          {(item.username[0] || 'U').toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '13px' }}>{item.username}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID #{item.id}</div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {item.connection_status === 'none' && (
                          <button
                            className="btn-primary"
                            onClick={() => handleSendRequest(item.username)}
                            disabled={sendingRequestTo === item.username}
                            style={{ padding: '6px 14px', fontSize: '12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                          >
                            <UserPlus size={14} />
                            <span>{sendingRequestTo === item.username ? t('workspace.btnSending') : t('workspace.btnSendRequest')}</span>
                          </button>
                        )}

                        {item.connection_status === 'pending_sent' && (
                          <span style={{ fontSize: '12px', color: 'var(--accent)', background: 'var(--accent-tint)', padding: '5px 12px', borderRadius: '6px', fontWeight: 500 }}>
                            {t('workspace.pendingSent')}
                          </span>
                        )}

                        {item.connection_status === 'pending_received' && (
                          <button
                            className="btn-primary"
                            onClick={() => handleAccept(item.connection_id)}
                            style={{ padding: '6px 14px', fontSize: '12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                          >
                            <Check size={14} />
                            <span>{t('workspace.pendingReceived')}</span>
                          </button>
                        )}

                        {item.connection_status === 'accepted' && (
                          <span style={{ fontSize: '12px', color: 'var(--success)', background: 'var(--success-tint)', padding: '5px 12px', borderRadius: '6px', fontWeight: 500, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <Check size={13} /> {t('workspace.connected')}
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {pendingRequests.length > 0 && (
        <div className="panel" style={{ borderColor: 'var(--accent)' }}>
          <div className="panel-head" style={{ color: 'var(--accent)' }}>{t('workspace.pendingApprovalHeader')}</div>
          <div className="panel-body" style={{ padding: 0 }}>
            {pendingRequests.map(c => {
              const reqName = c.requester_username || `User #${c.requester_id}`
              return (
                <div key={c.id} style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--surface-2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', color: 'var(--accent)' }}>
                      {(reqName[0] || 'U').toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{reqName}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {language === 'en' ? 'Wants to connect with you' : 'Ingin terhubung dengan Anda'}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button 
                      className="btn-primary" 
                      onClick={() => handleAccept(c.id)} 
                      style={{ padding: '6px 14px', height: 'auto', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Check size={14} /> {t('workspace.btnAccept')}
                    </button>
                    <button 
                      className="btn-secondary" 
                      onClick={() => handleReject(c.id)} 
                      style={{ padding: '6px 14px', height: 'auto', display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--danger)', borderColor: 'rgba(242, 85, 90, 0.2)' }}
                    >
                      <X size={14} /> {t('workspace.btnReject')}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">{t('workspace.activeConnections')}</div>
        <div className="panel-body" style={{ padding: 0 }}>
          {activeConnections.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>{t('workspace.noActiveConnections')}</div>
          ) : (
            currentActiveConnections.map(c => {
              const friendId = c.requester_id === user?.id ? c.recipient_id : c.requester_id
              const friendName = c.friend_username || (c.requester_id === user?.id ? c.recipient_username : c.requester_username) || String(friendId)
              return (
                <div key={c.id} style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: c === currentActiveConnections[currentActiveConnections.length - 1] ? 'none' : '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--accent-tint)', color: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
                      {(friendName[0] || 'U').toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{friendName}</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                        ID #{friendId} · {language === 'en' ? 'Connected since' : 'Terhubung sejak'} {new Date(c.created_at).toLocaleDateString(language === 'en' ? 'en-US' : 'id-ID', { day: '2-digit', month: 'short', year: 'numeric' })}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button 
                      className="btn-secondary" 
                      style={{ padding: '6px 12px', height: 'auto', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                      onClick={() => setShareRecipient(friendName)}
                    >
                      <Send size={14} /> {t('workspace.btnSendFile')}
                    </button>
                    <button 
                      className="btn-secondary" 
                      title={t('workspace.btnRemoveConnection')}
                      style={{ padding: '6px 10px', height: 'auto', display: 'inline-flex', alignItems: 'center', color: 'var(--text-muted)' }}
                      onClick={() => handleRemoveConnection(c.id, friendName)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              )
            })
          )}
        </div>
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--border)', background: 'var(--surface)', borderBottomLeftRadius: '8px', borderBottomRightRadius: '8px' }}>
            <button className="btn-secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>&larr; {t('common.prev')}</button>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{t('common.pageOf', { current: currentPage, total: totalPages })}</div>
            <button className="btn-secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} style={{ padding: '4px 10px', height: 'auto', fontSize: '12px' }}>{t('common.next')} &rarr;</button>
          </div>
        )}
      </div>
    </div>
  )
}
