import { useEffect, useRef } from 'react'

function formatDate(value) {
  if (!value) return 'Unavailable'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unavailable'

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function SummaryMetric({ label, value }) {
  return (
    <div className="investigation-metric">
      <span>{label}</span>
      <strong>{value ?? '—'}</strong>
    </div>
  )
}

function EventTimeline({ events, emptyMessage, onOpenInvestigation }) {
  if (!events?.length) {
    return <p className="investigation-empty">{emptyMessage}</p>
  }

  return (
    <ol className="investigation-event-list">
      {events.map((event) => (
        <li key={event.id}>
          <span className="event-marker" />
          <div className="event-list-content">
            <div className="event-list-topline">
              <strong>{event.eventType || 'Unknown event'}</strong>
              <time>{formatDate(event.timestamp)}</time>
            </div>
            <p>
              {event.username && (
                <span>
                  Account:{' '}
                  <button
                    className="investigation-link"
                    type="button"
                    onClick={() => onOpenInvestigation('username', event.username)}
                    aria-haspopup="dialog"
                  >
                    {event.username}
                  </button>
                </span>
              )}
              {event.sourceIp && (
                <span>
                  IP:{' '}
                  <button
                    className="investigation-link"
                    type="button"
                    onClick={() => onOpenInvestigation('ip', event.sourceIp)}
                    aria-haspopup="dialog"
                  >
                    {event.sourceIp}
                  </button>
                </span>
              )}
            </p>
          </div>
        </li>
      ))}
    </ol>
  )
}

function RelatedAlerts({ alerts, onOpenInvestigation }) {
  if (!alerts?.length) {
    return <p className="investigation-empty">No related alerts.</p>
  }

  return (
    <div className="investigation-related-list">
      {alerts.map((alert) => (
        <article className="related-alert" key={alert.id}>
          <div className="related-alert-heading">
            <span className={`severity-badge ${alert.severity?.toLowerCase() || 'unknown'}`}>
              <span />
              {alert.severity || 'Unknown'}
            </span>
            <time>{formatDate(alert.createdAt)}</time>
          </div>
          <button
            className="related-alert-link"
            type="button"
            onClick={() => onOpenInvestigation('alert', alert.id)}
            aria-haspopup="dialog"
          >
            {alert.description || 'No description provided'}
          </button>
          {alert.triggeringRule && (
            <span className="related-alert-rule">{alert.triggeringRule}</span>
          )}
        </article>
      ))}
    </div>
  )
}

function InvestigationDrawer({
  selection,
  data,
  loading,
  error,
  onClose,
  onOpenInvestigation,
}) {
  const closeButton = useRef(null)

  useEffect(() => {
    if (!selection) return undefined

    closeButton.current?.focus()
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') onClose()
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [selection, onClose])

  if (!selection) return null

  const title = selection.kind === 'ip'
    ? 'IP investigation'
    : selection.kind === 'username'
      ? 'Account investigation'
      : 'Alert investigation'

  return (
    <div
      className="investigation-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <aside
        className="investigation-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="investigation-title"
      >
        <header className="investigation-header">
          <div>
            <div className="eyebrow">INVESTIGATION</div>
            <h2 id="investigation-title">{title}</h2>
          </div>
          <button
            ref={closeButton}
            className="investigation-close"
            type="button"
            onClick={onClose}
            aria-label="Close investigation panel"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="m6 6 12 12M18 6 6 18" />
            </svg>
          </button>
        </header>

        <div className="investigation-body">
          {loading && !data && (
            <div className="investigation-loading">Loading investigation…</div>
          )}
          {error && <div className="investigation-error" role="alert">{error}</div>}

          {!loading && !error && data && selection.kind === 'ip' && (
            <>
              <div className="investigation-entity">
                <span className="entity-type-label">SOURCE IP ADDRESS</span>
                <strong className="entity-ip">{data.ipAddress}</strong>
              </div>
              <div className="investigation-metrics">
                <SummaryMetric label="Failed logins" value={data.failedLogins?.toLocaleString()} />
                <SummaryMetric label="Successful logins" value={data.successfulLogins?.toLocaleString()} />
                <SummaryMetric label="First seen" value={formatDate(data.firstSeen)} />
                <SummaryMetric label="Last seen" value={formatDate(data.lastSeen)} />
              </div>
              <section className="investigation-section">
                <h3>Related alerts <span>{data.relatedAlerts?.length || 0}</span></h3>
                <RelatedAlerts
                  alerts={data.relatedAlerts}
                  onOpenInvestigation={onOpenInvestigation}
                />
              </section>
              <section className="investigation-section">
                <h3>Threat intelligence matches <span>{data.threatMatches?.length || 0}</span></h3>
                {data.threatMatches?.length ? (
                  <div className="investigation-related-list">
                    {data.threatMatches.map((match) => (
                      <article className="related-alert intel-match" key={match.id}>
                        <div className="related-alert-heading">
                          <span className="intel-critical-badge"><span />CRITICAL</span>
                          <time>{formatDate(match.detectedAt)}</time>
                        </div>
                        <p>{match.threatType} · reputation {match.reputationScore}/100</p>
                        <span className="related-alert-rule">{match.associatedEvent}</span>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p className="investigation-empty">No threat intelligence matches.</p>
                )}
              </section>
              <section className="investigation-section">
                <h3>Activity timeline <span>{data.activityTimeline?.length || 0}</span></h3>
                <EventTimeline
                  events={data.activityTimeline}
                  emptyMessage="No activity found for this IP."
                  onOpenInvestigation={onOpenInvestigation}
                />
              </section>
            </>
          )}

          {!loading && !error && data && selection.kind === 'username' && (
            <>
              <div className="investigation-entity">
                <span className="entity-type-label">TARGETED ACCOUNT</span>
                <strong>{data.username}</strong>
              </div>
              <div className="investigation-metrics">
                <SummaryMetric label="Failed logins" value={data.failedLogins?.toLocaleString()} />
                <SummaryMetric label="Successful logins" value={data.successfulLogins?.toLocaleString()} />
                <SummaryMetric label="Account lockouts" value={data.accountLockouts?.toLocaleString()} />
              </div>
              <section className="investigation-section">
                <h3>Associated source IPs <span>{data.sourceIps?.length || 0}</span></h3>
                {data.sourceIps?.length ? (
                  <div className="investigation-ip-list">
                    {data.sourceIps.map((ip) => (
                      <button
                        className="investigation-link investigation-ip-chip"
                        type="button"
                        key={ip}
                        onClick={() => onOpenInvestigation('ip', ip)}
                        aria-haspopup="dialog"
                      >
                        {ip}
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="investigation-empty">No source IPs found.</p>
                )}
              </section>
              <section className="investigation-section">
                <h3>Related alerts <span>{data.relatedAlerts?.length || 0}</span></h3>
                <RelatedAlerts
                  alerts={data.relatedAlerts}
                  onOpenInvestigation={onOpenInvestigation}
                />
              </section>
              <section className="investigation-section">
                <h3>Authentication timeline <span>{data.activityTimeline?.length || 0}</span></h3>
                <EventTimeline
                  events={data.activityTimeline}
                  emptyMessage="No authentication activity found for this account."
                  onOpenInvestigation={onOpenInvestigation}
                />
              </section>
            </>
          )}

          {!loading && !error && data && selection.kind === 'alert' && (
            <>
              <div className="alert-investigation-top">
                <span className={`severity-badge ${data.severity?.toLowerCase() || 'unknown'}`}>
                  <span />
                  {data.severity || 'Unknown'}
                </span>
                <time>{formatDate(data.detectionTime)}</time>
              </div>
              <p className="alert-investigation-description">
                {data.description || 'No alert description provided.'}
              </p>
              <section className="investigation-section alert-facts">
                <h3>Detection details</h3>
                <div className="alert-fact">
                  <span>Triggering rule</span>
                  <strong>{data.triggeringRule || 'Unspecified'}</strong>
                </div>
                <div className="alert-fact">
                  <span>Affected source IPs</span>
                  <div className="investigation-ip-list">
                    {data.affectedSourceIps?.length
                      ? data.affectedSourceIps.map((ip) => (
                        <button
                          className="investigation-link investigation-ip-chip"
                          type="button"
                          key={ip}
                          onClick={() => onOpenInvestigation('ip', ip)}
                          aria-haspopup="dialog"
                        >
                          {ip}
                        </button>
                      ))
                      : <strong>Not recorded</strong>}
                  </div>
                </div>
                <div className="alert-fact">
                  <span>Affected usernames</span>
                  <div className="investigation-ip-list">
                    {data.affectedUsernames?.length
                      ? data.affectedUsernames.map((username) => (
                        <button
                          className="investigation-link investigation-ip-chip"
                          type="button"
                          key={username}
                          onClick={() => onOpenInvestigation('username', username)}
                          aria-haspopup="dialog"
                        >
                          {username}
                        </button>
                      ))
                      : <strong>Not recorded</strong>}
                  </div>
                </div>
              </section>
              <section className="investigation-section">
                <h3>IP intelligence</h3>
                {data.ipIntelligence?.length ? (
                  <div className="ip-intelligence-list">
                    {data.ipIntelligence.map((ipDetails) => (
                      <article className="ip-intelligence-card" key={ipDetails.ipAddress}>
                        <button
                          className="investigation-link ip-intelligence-address"
                          type="button"
                          onClick={() => onOpenInvestigation('ip', ipDetails.ipAddress)}
                          aria-haspopup="dialog"
                        >
                          {ipDetails.ipAddress}
                        </button>
                        <div className="investigation-metrics ip-intelligence-metrics">
                          <SummaryMetric
                            label="Failed logins"
                            value={ipDetails.failedLogins?.toLocaleString()}
                          />
                          <SummaryMetric
                            label="Successful logins"
                            value={ipDetails.successfulLogins?.toLocaleString()}
                          />
                          <SummaryMetric label="First seen" value={formatDate(ipDetails.firstSeen)} />
                          <SummaryMetric label="Last seen" value={formatDate(ipDetails.lastSeen)} />
                        </div>
                        <div className="ip-intelligence-context">
                          <h4>Related alerts</h4>
                          <RelatedAlerts
                            alerts={ipDetails.relatedAlerts}
                            onOpenInvestigation={onOpenInvestigation}
                          />
                          <h4>Threat intelligence matches</h4>
                          {ipDetails.threatMatches?.length ? (
                            ipDetails.threatMatches.map((match) => (
                              <p className="ip-match-summary" key={match.id}>
                                <span className="intel-critical-badge"><span />CRITICAL</span>
                                {match.threatType} · reputation {match.reputationScore}/100 ·{' '}
                                {formatDate(match.detectedAt)}
                              </p>
                            ))
                          ) : (
                            <p className="investigation-empty">No intelligence matches.</p>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p className="investigation-empty">No source IP context is available.</p>
                )}
              </section>
              <section className="investigation-section">
                <h3>Supporting log events <span>{data.supportingEvents?.length || 0}</span></h3>
                <EventTimeline
                  events={data.supportingEvents}
                  emptyMessage="No supporting log events were recorded for this alert."
                  onOpenInvestigation={onOpenInvestigation}
                />
              </section>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}

export default InvestigationDrawer
