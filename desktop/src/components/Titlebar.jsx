import React from 'react'
import { Shield, Minus, Square, X } from 'lucide-react'

export default function Titlebar() {
  return (
    <div className="titlebar">
      <div className="titlebar-left">
        <Shield className="titlebar-icon" />
        <span className="titlebar-title">Faycryptor</span>
      </div>
      <div className="titlebar-controls">
        <button className="tb-btn" onClick={() => window.electronAPI?.minimize()}>
          <Minus size={14} />
        </button>
        <button className="tb-btn" onClick={() => window.electronAPI?.toggleMaximize?.() || window.electronAPI?.maximize?.()}>
          <Square size={12} />
        </button>
        <button className="tb-btn close" onClick={() => window.electronAPI?.close()}>
          <X size={14} />
        </button>
      </div>
    </div>
  )
}
