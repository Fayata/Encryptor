import React, { useState } from 'react'
import { Building2, Users } from 'lucide-react'
import OrganizationView from './OrganizationView'
import ConnectionsView from './ConnectionsView'
import { useTranslation } from '../lib/i18n'

export default function WorkspaceView({
  user,
  masterKey,
  activeOrg,
  setActiveOrg,
  userOrgs,
  fetchUserOrgs,
  initialTab = 'org'
}) {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState(initialTab)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Sub-tab Navigation */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        borderBottom: '1px solid var(--border)',
        paddingBottom: '12px'
      }}>
        <button
          className={activeTab === 'org' ? 'btn-primary' : 'btn-secondary'}
          onClick={() => setActiveTab('org')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            fontSize: '13px',
            fontWeight: activeTab === 'org' ? 600 : 500
          }}
        >
          <Building2 size={15} />
          <span>{t('workspace.tabOrg')} {activeOrg ? `(${activeOrg.name})` : ''}</span>
        </button>

        <button
          className={activeTab === 'connections' ? 'btn-primary' : 'btn-secondary'}
          onClick={() => setActiveTab('connections')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            fontSize: '13px',
            fontWeight: activeTab === 'connections' ? 600 : 500
          }}
        >
          <Users size={15} />
          <span>{t('workspace.tabConnections')}</span>
        </button>
      </div>

      {/* Tab Content */}
      <div style={{ width: '100%' }}>
        {activeTab === 'org' ? (
          <OrganizationView
            user={user}
            masterKey={masterKey}
            activeOrg={activeOrg}
            setActiveOrg={setActiveOrg}
            userOrgs={userOrgs}
            fetchUserOrgs={fetchUserOrgs}
          />
        ) : (
          <ConnectionsView
            user={user}
            masterKey={masterKey}
          />
        )}
      </div>
    </div>
  )
}
