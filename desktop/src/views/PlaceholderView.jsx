import React from 'react'

export default function PlaceholderView({ title, desc }) {
  return (
    <div className="view-panel center-panel">
      <h2>{title}</h2>
      <p>{desc}</p>
    </div>
  )
}
