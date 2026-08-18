import React from 'react'
import { Shield } from 'lucide-react'

export default function AboutView() {
  return (
    <div className="view-narrow">
      <div className="panel" style={{ textAlign: 'center', padding: '48px 24px' }}>
        <Shield size={64} className="auth-icon" style={{ margin: '0 auto 16px' }} />
        <h2 style={{ marginBottom: '32px' }}>Faycryptor</h2>
        
        <div style={{ color: 'var(--text-secondary)', marginBottom: '32px', lineHeight: '1.6' }}>
          <p>Advanced local encryption tool with cloud vault synchronization.</p>
          <p>Built for security, speed, and seamless key management.</p>
        </div>

        <div style={{ backgroundColor: 'var(--surface-2)', padding: '16px', borderRadius: '8px', textAlign: 'left', display: 'inline-block', minWidth: '250px' }}>
          <h4 style={{ marginBottom: '12px', color: 'var(--text-primary)' }}>Supported Algorithms</h4>
          <ul style={{ color: 'var(--text-secondary)', paddingLeft: '20px', lineHeight: '1.8' }}>
            <li>FayCipher (DAG Multi-Layer)</li>
            <li>AES-256-GCM</li>
            <li>AES-256-CBC</li>
            <li>XChaCha20-Poly1305</li>
            <li>3DES</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
