import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import './App.css'
import InvestigationDrawer from './InvestigationDrawer.jsx'

const DistributionDonut = lazy(() => import('./DistributionDonut.jsx'))
const AlertTimelineChart = lazy(() => import('./AlertTimelineChart.jsx'))
const API_BASE_URL = '/api'

const metricCards = [
  {
    label: 'Total logs',
    key: 'totalLogs',
    description: 'Events ingested',
    icon: 'logs',
    tone: 'blue',
  },
  {
    label: 'Total alerts',
    key: 'totalAlerts',
    description: 'Threats detected',
    icon: 'alerts',
    tone: 'violet',
  },
  {
    label: 'High alerts',
    key: 'highAlerts',
    description: 'Require attention',
    icon: 'high',
    tone: 'amber',
  },
  {
    label: 'Critical alerts',
    key: 'criticalAlerts',
    description: 'Immediate action',
    icon: 'critical',
    tone: 'red',
  },
]

function MetricIcon({ type }) {
  const paths = {
    logs: (
      <>
        <path d="M8 3h7l5 5v13H8z" />
        <path d="M15 3v5h5M11 13h6M11 17h6M4 7v14h4" />
      </>
    ),
    alerts: (
      <>
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" />
        <path d="M10 21h4" />
      </>
    ),
    high: (
      <>
        <path d="m12 3 10 18H2L12 3Z" />
        <path d="M12 9v5M12 18h.01" />
      </>
    ),
    critical: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v6M12 17h.01" />
      </>
    ),
  }

  return (
    <svg
      aria-hidden="true"
      className="metric-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths[type]}
    </svg>
  )
}

function formatDate(value) {
  if (!value) return 'Time unavailable'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Time unavailable'

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function formatAnalyticsRows(rows) {
  if (!Array.isArray(rows) || !rows.every((row) => Array.isArray(row))) {
    throw new Error('The analytics response was not in the expected format.')
  }

  return rows
    .map(([name, attempts]) => ({
      name: name == null ? '' : String(name),
      attempts: Number(attempts),
    }))
    .filter((row) => row.name && Number.isFinite(row.attempts))
    .sort((left, right) => right.attempts - left.attempts)
    .slice(0, 10)
}

function formatDistributionRows(rows) {
  if (!Array.isArray(rows) || !rows.every((row) => Array.isArray(row))) {
    throw new Error('The chart response was not in the expected format.')
  }

  return rows
    .map(([name, value]) => ({
      name: name == null ? '' : String(name),
      value: Number(value),
    }))
    .filter((row) => row.name && Number.isFinite(row.value) && row.value >= 0)
    .sort((left, right) => right.value - left.value)
}

function formatTimelineRows(rows) {
  if (!Array.isArray(rows)) {
    throw new Error('The timeline response was not in the expected format.')
  }

  return rows.map((row) => {
    const timestamp = new Date(row.timestamp).getTime()
    const high = Number(row.high)
    const critical = Number(row.critical)

    if (
      !Number.isFinite(timestamp) ||
      !Number.isFinite(high) ||
      !Number.isFinite(critical)
    ) {
      throw new Error('The timeline response contained invalid alert data.')
    }

    return { timestamp, high, critical }
  })
}

function formatThreatDetections(rows) {
  if (!Array.isArray(rows)) {
    throw new Error('The threat intelligence response was not in the expected format.')
  }

  return rows.map((detection) => {
    if (!detection || typeof detection !== 'object') {
      throw new Error('The threat intelligence response contained invalid data.')
    }

    const reputationScore = Number(detection.reputationScore)
    if (
      typeof detection.ipAddress !== 'string' ||
      typeof detection.threatType !== 'string' ||
      !Number.isFinite(reputationScore)
    ) {
      throw new Error('The threat intelligence response contained invalid data.')
    }

    return { ...detection, reputationScore }
  })
}

const eventColors = {
  LOGIN_FAILED: '#e35b61',
  LOGIN_SUCCESS: '#45b58b',
  PASSWORD_RESET: '#e2a443',
  ACCOUNT_LOCKED: '#8068d7',
}

const severityColors = {
  CRITICAL: '#e35b61',
  HIGH: '#e28b45',
  MEDIUM: '#e2ad43',
  LOW: '#45b58b',
}

function getRiskLevel(attempts) {
  if (attempts >= 10) return 'high'
  if (attempts >= 5) return 'medium'
  return 'low'
}

function App() {
  const [stats, setStats] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [attackingIps, setAttackingIps] = useState([])
  const [targetedUsers, setTargetedUsers] = useState([])
  const [eventDistribution, setEventDistribution] = useState([])
  const [severityDistribution, setSeverityDistribution] = useState([])
  const [timelineData, setTimelineData] = useState([])
  const [timelineRange, setTimelineRange] = useState('24h')
  const [timelineLoading, setTimelineLoading] = useState(true)
  const [timelineError, setTimelineError] = useState('')
  const [threatDetections, setThreatDetections] = useState([])
  const [threatIntelLoading, setThreatIntelLoading] = useState(true)
  const [threatIntelError, setThreatIntelError] = useState('')
  const [indicatorFile, setIndicatorFile] = useState(null)
  const [indicatorImporting, setIndicatorImporting] = useState(false)
  const [indicatorImportError, setIndicatorImportError] = useState('')
  const [indicatorImportMessage, setIndicatorImportMessage] = useState('')
  const [investigationSelection, setInvestigationSelection] = useState(null)
  const [investigationData, setInvestigationData] = useState(null)
  const [investigationLoading, setInvestigationLoading] = useState(false)
  const [investigationError, setInvestigationError] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const indicatorFileInput = useRef(null)

  const refresh = useCallback(() => setRefreshKey((key) => key + 1), [])
  const openInvestigation = useCallback((kind, value) => {
    setInvestigationSelection({ kind, value })
    setInvestigationData(null)
    setInvestigationError('')
    setInvestigationLoading(true)
  }, [])
  const closeInvestigation = useCallback(() => {
    setInvestigationSelection(null)
    setInvestigationData(null)
    setInvestigationError('')
  }, [])

  useEffect(() => {
    const controller = new AbortController()

    async function loadDashboard() {
      setLoading(true)
      setError('')

      try {
        const [
          statsResponse,
          alertsResponse,
          ipsResponse,
          usersResponse,
          eventsResponse,
          severityResponse,
        ] = await Promise.all([
          fetch(`${API_BASE_URL}/stats`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/alerts`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/analytics/top-ips`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/analytics/top-users`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/analytics/event-distribution`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/analytics/alert-severity`, { signal: controller.signal }),
        ])

        if (
          !statsResponse.ok ||
          !alertsResponse.ok ||
          !ipsResponse.ok ||
          !usersResponse.ok ||
          !eventsResponse.ok ||
          !severityResponse.ok
        ) {
          throw new Error('The dashboard data could not be loaded.')
        }

        const [
          statsData,
          alertsData,
          ipsData,
          usersData,
          eventsData,
          severityData,
        ] = await Promise.all([
          statsResponse.json(),
          alertsResponse.json(),
          ipsResponse.json(),
          usersResponse.json(),
          eventsResponse.json(),
          severityResponse.json(),
        ])

        if (!Array.isArray(alertsData)) {
          throw new Error('The alerts response was not in the expected format.')
        }

        setStats(statsData)
        setAlerts(alertsData)
        setAttackingIps(formatAnalyticsRows(ipsData))
        setTargetedUsers(formatAnalyticsRows(usersData))
        setEventDistribution(formatDistributionRows(eventsData))
        setSeverityDistribution(formatDistributionRows(severityData))
        setLastUpdated(new Date())
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setError(loadError.message || 'Unable to connect to the dashboard API.')
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    loadDashboard()
    return () => controller.abort()
  }, [refreshKey])

  useEffect(() => {
    if (!investigationSelection) return undefined

    const controller = new AbortController()

    async function loadInvestigation() {
      try {
        let endpoint
        if (investigationSelection.kind === 'ip') {
          const query = new URLSearchParams({ address: investigationSelection.value })
          endpoint = `${API_BASE_URL}/investigations/ip?${query}`
        } else if (investigationSelection.kind === 'username') {
          const query = new URLSearchParams({ username: investigationSelection.value })
          endpoint = `${API_BASE_URL}/investigations/username?${query}`
        } else {
          endpoint = `${API_BASE_URL}/investigations/alert/${investigationSelection.value}`
        }

        const response = await fetch(endpoint, { signal: controller.signal })
        const result = await response.json()
        if (!response.ok) {
          throw new Error(result.detail || 'Investigation details could not be loaded.')
        }

        setInvestigationData(result)
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setInvestigationError(
            loadError.message || 'Unable to load investigation details.',
          )
        }
      } finally {
        if (!controller.signal.aborted) setInvestigationLoading(false)
      }
    }

    loadInvestigation()
    return () => controller.abort()
  }, [investigationSelection])

  useEffect(() => {
    const controller = new AbortController()

    async function loadTimeline() {
      setTimelineLoading(true)
      setTimelineError('')

      try {
        const response = await fetch(
          `${API_BASE_URL}/analytics/alert-timeline?range=${timelineRange}`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error('Alert activity could not be loaded.')
        }

        const data = await response.json()
        setTimelineData(formatTimelineRows(data))
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setTimelineError(
            loadError.message || 'Unable to load alert activity.',
          )
        }
      } finally {
        if (!controller.signal.aborted) setTimelineLoading(false)
      }
    }

    loadTimeline()
    return () => controller.abort()
  }, [timelineRange, refreshKey])

  useEffect(() => {
    const controller = new AbortController()

    async function loadThreatDetections() {
      setThreatIntelLoading(true)
      setThreatIntelError('')

      try {
        const response = await fetch(
          `${API_BASE_URL}/threat-intelligence/detections`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error('Threat intelligence detections could not be loaded.')
        }

        setThreatDetections(formatThreatDetections(await response.json()))
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setThreatIntelError(
            loadError.message || 'Unable to load threat intelligence detections.',
          )
        }
      } finally {
        if (!controller.signal.aborted) setThreatIntelLoading(false)
      }
    }

    loadThreatDetections()
    const refreshInterval = window.setInterval(loadThreatDetections, 30_000)

    return () => {
      controller.abort()
      window.clearInterval(refreshInterval)
    }
  }, [refreshKey])

  async function importThreatIndicators(event) {
    event.preventDefault()
    setIndicatorImportError('')
    setIndicatorImportMessage('')

    if (!indicatorFile) {
      setIndicatorImportError('Select a CSV file to import.')
      return
    }

    setIndicatorImporting(true)
    try {
      const formData = new FormData()
      formData.append('file', indicatorFile)
      const response = await fetch(
        `${API_BASE_URL}/threat-intelligence/indicators/import`,
        { method: 'POST', body: formData },
      )
      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.detail || 'The CSV import failed.')
      }

      setIndicatorImportMessage(
        `Imported ${result.importedCount} new indicators and updated ${result.updatedCount}.`,
      )
      setIndicatorFile(null)
      if (indicatorFileInput.current) indicatorFileInput.current.value = ''
      refresh()
    } catch (importError) {
      setIndicatorImportError(
        importError.message || 'Unable to import the CSV file.',
      )
    } finally {
      setIndicatorImporting(false)
    }
  }

  const alertCount = (severity) =>
    alerts.filter(
      (alert) => alert.severity?.trim().toLowerCase() === severity,
    ).length

  const metrics = {
    totalLogs: stats?.totalLogs,
    totalAlerts: stats?.totalAlerts,
    highAlerts: alertCount('high'),
    criticalAlerts: alertCount('critical'),
  }
  const recentAlerts = [...alerts]
    .sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt))
    .slice(0, 5)

  return (
    <main className="dashboard-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="Sentinel home">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" fill="none">
              <path
                d="M16 3 27 7v8c0 7-4.7 11.6-11 14C9.7 26.6 5 22 5 15V7l11-4Z"
                stroke="currentColor"
                strokeWidth="2"
              />
              <path
                d="m11 16 3.2 3.2L21 12"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <span className="brand-name">sentinel<span>.</span></span>
        </a>

        <div className="sidebar-label">Workspace</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-link active" href="#overview" aria-current="page">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <rect x="3" y="3" width="8" height="8" rx="1.5" />
              <rect x="13" y="3" width="8" height="5" rx="1.5" />
              <rect x="13" y="10" width="8" height="11" rx="1.5" />
              <rect x="3" y="13" width="8" height="8" rx="1.5" />
            </svg>
            Overview
          </a>
          <a className="nav-link" href="#recent-alerts">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" />
            </svg>
            Alerts
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot" />
            <span>Monitoring active</span>
          </div>
          <p>Security overview</p>
        </div>
      </aside>

      <section className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="breadcrumb-divider">/</span>
            <strong>Overview</strong>
          </div>
          <div className="topbar-right">
            <span className="live-indicator"><span /> Live</span>
            <button
              className="refresh-button"
              type="button"
              onClick={refresh}
              disabled={loading}
              aria-label="Refresh dashboard data"
            >
              <svg
                viewBox="0 0 24 24"
                aria-hidden="true"
                className={loading ? 'refresh-icon spinning' : 'refresh-icon'}
              >
                <path d="M20 7v5h-5M4 17v-5h5" />
                <path d="M5.6 9a7 7 0 0 1 11.6-2L20 12M4 12l2.8 5a7 7 0 0 0 11.6-2" />
              </svg>
              Refresh
            </button>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS</div>
              <h1>Dashboard</h1>
              <p className="page-subtitle">
                Monitor your security events and keep threats in check.
              </p>
            </div>
            <div className="updated-at" aria-live="polite">
              <span className="updated-dot" />
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`
                : 'Connecting to your data'}
            </div>
          </section>

          {error && (
            <div className="error-banner" role="alert">
              <span>{error}</span>
              <button type="button" onClick={refresh}>Try again</button>
            </div>
          )}

          <section className="metrics-grid" aria-label="Security metrics">
            {metricCards.map((metric) => (
              <article className={`metric-card ${metric.tone}`} key={metric.key}>
                <div className="metric-card-top">
                  <span className="metric-label">{metric.label}</span>
                  <span className="metric-icon-wrap">
                    <MetricIcon type={metric.icon} />
                  </span>
                </div>
                <div className="metric-value" aria-live="polite">
                  {loading && metrics[metric.key] == null
                    ? <span className="skeleton-value" aria-label="Loading" />
                    : metrics[metric.key] == null
                      ? '—'
                      : metrics[metric.key].toLocaleString()}
                </div>
                <div className="metric-description">{metric.description}</div>
              </article>
            ))}
          </section>

          <section className="alerts-panel" id="recent-alerts">
            <div className="panel-heading">
              <div>
                <h2>Recent alerts</h2>
                <p>Latest threats detected across your environment</p>
              </div>
              <span className="alert-count">
                {loading ? 'Loading' : `${alerts.length} total`}
              </span>
            </div>

            <div className="alerts-table-wrap">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Description</th>
                    <th scope="col">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((alert, index) => {
                    const severity = alert.severity?.trim().toLowerCase() || 'unknown'
                    return (
                      <tr key={alert.id ?? `${alert.createdAt}-${index}`}>
                        <td>
                          <span className={`severity-badge ${severity}`}>
                            <span />
                            {alert.severity || 'Unknown'}
                          </span>
                        </td>
                        <td className="alert-description">
                          {alert.id != null ? (
                            <button
                              className="investigation-link"
                              type="button"
                              onClick={() => openInvestigation('alert', alert.id)}
                              aria-haspopup="dialog"
                            >
                              {alert.description || 'No description provided'}
                            </button>
                          ) : (
                            alert.description || 'No description provided'
                          )}
                        </td>
                        <td className="alert-time">{formatDate(alert.createdAt)}</td>
                      </tr>
                    )
                  })}
                  {!loading && recentAlerts.length === 0 && (
                    <tr>
                      <td className="empty-state" colSpan="3">
                        No alerts to show yet. New detections will appear here.
                      </td>
                    </tr>
                  )}
                  {loading && recentAlerts.length === 0 && (
                    <tr>
                      <td className="empty-state" colSpan="3">Loading alerts…</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="analytics-section" aria-labelledby="analytics-title">
            <div className="analytics-section-heading">
              <div>
                <div className="eyebrow">INVESTIGATION</div>
                <h2 id="analytics-title">Threat sources &amp; targeted accounts</h2>
                <p>Failed login activity ranked by frequency</p>
              </div>
              <span className="analytics-window">Top 10</span>
            </div>

            <div className="analytics-grid">
              <article className="analytics-card">
                <div className="analytics-card-heading">
                  <div className="analytics-card-icon ip-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <circle cx="12" cy="12" r="8.5" />
                      <path d="M3.8 9h16.4M3.8 15h16.4M12 3.5a13.5 13.5 0 0 1 0 17M12 3.5a13.5 13.5 0 0 0 0 17" />
                    </svg>
                  </div>
                  <div>
                    <h3>Top attacking IPs</h3>
                    <p>Sources of failed login attempts</p>
                  </div>
                </div>
                <div className="analytics-table-wrap">
                  <table className="analytics-table">
                    <thead>
                      <tr>
                        <th scope="col">IP Address</th>
                        <th scope="col">Failed Login Attempts</th>
                        <th scope="col">Threat Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackingIps.map((source) => {
                        const risk = getRiskLevel(source.attempts)
                        return (
                          <tr key={source.name}>
                            <td className="analytics-identity ip-address">
                              <button
                                className="investigation-link"
                                type="button"
                                onClick={() => openInvestigation('ip', source.name)}
                                aria-haspopup="dialog"
                              >
                                {source.name}
                              </button>
                            </td>
                            <td className="attempt-count">{source.attempts.toLocaleString()}</td>
                            <td>
                              <span className={`risk-badge ${risk}`}>{risk}</span>
                            </td>
                          </tr>
                        )
                      })}
                      {!loading && attackingIps.length === 0 && (
                        <tr>
                          <td className="analytics-empty" colSpan="3">No attacking IPs found.</td>
                        </tr>
                      )}
                      {loading && attackingIps.length === 0 && (
                        <tr>
                          <td className="analytics-empty" colSpan="3">Loading IP analytics…</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </article>

              <article className="analytics-card">
                <div className="analytics-card-heading">
                  <div className="analytics-card-icon user-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <circle cx="12" cy="8" r="3.5" />
                      <path d="M5 20c.5-3.5 3.1-5.5 7-5.5s6.5 2 7 5.5" />
                    </svg>
                  </div>
                  <div>
                    <h3>Top targeted users</h3>
                    <p>Accounts with failed login attempts</p>
                  </div>
                </div>
                <div className="analytics-table-wrap">
                  <table className="analytics-table">
                    <thead>
                      <tr>
                        <th scope="col">Username</th>
                        <th scope="col">Failed Login Attempts</th>
                        <th scope="col">Risk Level</th>
                      </tr>
                    </thead>
                    <tbody>
                      {targetedUsers.map((user) => {
                        const risk = getRiskLevel(user.attempts)
                        return (
                          <tr key={user.name}>
                            <td className="analytics-identity">
                              <button
                                className="investigation-link"
                                type="button"
                                onClick={() => openInvestigation('username', user.name)}
                                aria-haspopup="dialog"
                              >
                                {user.name}
                              </button>
                            </td>
                            <td className="attempt-count">{user.attempts.toLocaleString()}</td>
                            <td>
                              <span className={`risk-badge ${risk}`}>{risk}</span>
                            </td>
                          </tr>
                        )
                      })}
                      {!loading && targetedUsers.length === 0 && (
                        <tr>
                          <td className="analytics-empty" colSpan="3">No targeted accounts found.</td>
                        </tr>
                      )}
                      {loading && targetedUsers.length === 0 && (
                        <tr>
                          <td className="analytics-empty" colSpan="3">Loading account analytics…</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </article>
            </div>
          </section>

          <section className="trends-section" aria-labelledby="trends-title">
            <div className="analytics-section-heading">
              <div>
                <div className="eyebrow">SECURITY TRENDS</div>
                <h2 id="trends-title">Threat activity &amp; security trends</h2>
                <p>Understand event patterns and alert severity across your environment</p>
              </div>
            </div>

            <div className="trends-grid">
              <article className="trend-card">
                <div className="trend-card-heading">
                  <div>
                    <h3>Event distribution</h3>
                    <p>Security events by type</p>
                  </div>
                  <span className="trend-icon event-trend-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <path d="M4 19V9M10 19V5M16 19v-7M22 19H2" />
                    </svg>
                  </span>
                </div>
                <Suspense fallback={<div className="trend-empty">Loading chart…</div>}>
                  <DistributionDonut
                    data={eventDistribution}
                    colors={eventColors}
                    unit="Events"
                    loading={loading}
                  />
                </Suspense>
              </article>

              <article className="trend-card">
                <div className="trend-card-heading">
                  <div>
                    <h3>Alert severity distribution</h3>
                    <p>Alerts grouped by severity</p>
                  </div>
                  <span className="trend-icon severity-trend-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24">
                      <path d="m12 3 10 18H2L12 3Z" />
                      <path d="M12 9v5M12 18h.01" />
                    </svg>
                  </span>
                </div>
                <Suspense fallback={<div className="trend-empty">Loading chart…</div>}>
                  <DistributionDonut
                    data={severityDistribution}
                    colors={severityColors}
                    unit="Alerts"
                    loading={loading}
                  />
                </Suspense>
              </article>
            </div>
          </section>

          <section className="timeline-section" aria-labelledby="timeline-title">
            <div className="analytics-section-heading">
              <div>
                <div className="eyebrow">ALERT ACTIVITY</div>
                <h2 id="timeline-title">Threat timeline &amp; alert activity</h2>
                <p>See when high-priority threats were detected</p>
              </div>
            </div>

            <article className="timeline-card">
              <div className="timeline-card-heading">
                <div>
                  <h3>Security alerts over time</h3>
                  <p>
                    {timelineRange === '24h'
                      ? 'Hourly alert counts'
                      : 'Daily alert counts'}
                  </p>
                </div>
                <label className="range-control">
                  <span>Time range</span>
                  <select
                    value={timelineRange}
                    onChange={(event) => setTimelineRange(event.target.value)}
                    aria-label="Select alert timeline range"
                  >
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                  </select>
                </label>
              </div>

              {timelineError ? (
                <div className="timeline-error" role="alert">
                  {timelineError}
                </div>
              ) : (
                <Suspense fallback={<div className="timeline-empty">Loading chart…</div>}>
                  <AlertTimelineChart
                    data={timelineData}
                    range={timelineRange}
                    loading={timelineLoading}
                  />
                </Suspense>
              )}
            </article>
          </section>

          <section className="threat-intel-section" aria-labelledby="threat-intel-title">
            <div className="analytics-section-heading">
              <div>
                <div className="eyebrow">INDICATOR CORRELATION</div>
                <h2 id="threat-intel-title">Threat intelligence</h2>
                <p>Enrich incoming security events with known malicious IP indicators</p>
              </div>
            </div>

            <article className="threat-intel-panel">
              <div className="threat-intel-header">
                <div>
                  <h3>Recent intelligence matches</h3>
                  <p>
                    {threatIntelLoading
                      ? 'Loading detections'
                      : `${threatDetections.length} recent detections`}
                  </p>
                </div>
                <form
                  className="indicator-import-form"
                  onSubmit={importThreatIndicators}
                >
                  <label className="indicator-file-picker">
                    <span>{indicatorFile?.name || 'Choose CSV'}</span>
                    <input
                      ref={indicatorFileInput}
                      type="file"
                      accept=".csv,text/csv"
                      onChange={(changeEvent) => {
                        setIndicatorFile(changeEvent.target.files?.[0] || null)
                        setIndicatorImportError('')
                        setIndicatorImportMessage('')
                      }}
                      aria-label="Choose threat indicators CSV"
                    />
                  </label>
                  <button
                    className="indicator-import-button"
                    type="submit"
                    disabled={indicatorImporting || !indicatorFile}
                  >
                    {indicatorImporting ? 'Importing…' : 'Import indicators'}
                  </button>
                </form>
              </div>

              <div className="indicator-import-status" aria-live="polite">
                <span>CSV columns: ip_address, threat_type, reputation_score</span>
                {indicatorImportMessage && (
                  <strong className="import-success">{indicatorImportMessage}</strong>
                )}
                {indicatorImportError && (
                  <strong className="import-error" role="alert">
                    {indicatorImportError}
                  </strong>
                )}
              </div>

              {threatIntelError ? (
                <div className="threat-intel-error" role="alert">
                  {threatIntelError}
                </div>
              ) : (
                <div className="threat-intel-table-wrap">
                  <table className="threat-intel-table">
                    <thead>
                      <tr>
                        <th scope="col">Malicious IP Address</th>
                        <th scope="col">Threat Type</th>
                        <th scope="col">Detection Time</th>
                        <th scope="col">Associated Event</th>
                        <th scope="col">Reputation Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threatDetections.map((detection) => (
                        <tr key={detection.id}>
                          <td>
                            <button
                              className="investigation-link intel-ip"
                              type="button"
                              onClick={() => openInvestigation('ip', detection.ipAddress)}
                              aria-haspopup="dialog"
                            >
                              {detection.ipAddress}
                            </button>
                            <span className="intel-critical-badge">
                              <span />
                              CRITICAL
                            </span>
                          </td>
                          <td className="intel-threat-type">{detection.threatType}</td>
                          <td className="intel-detected-at">
                            {formatDate(detection.detectedAt)}
                          </td>
                          <td>
                            <span className="intel-event-badge">
                              {detection.associatedEvent || 'Unknown'}
                            </span>
                          </td>
                          <td>
                            <div className="reputation-score">
                              <span>{detection.reputationScore}/100</span>
                              <span className="reputation-track">
                                <span style={{ width: `${detection.reputationScore}%` }} />
                              </span>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {!threatIntelLoading && threatDetections.length === 0 && (
                        <tr>
                          <td className="threat-intel-empty" colSpan="5">
                            No indicator matches yet. Import a CSV; matching incoming
                            events will appear here.
                          </td>
                        </tr>
                      )}
                      {threatIntelLoading && threatDetections.length === 0 && (
                        <tr>
                          <td className="threat-intel-empty" colSpan="5">
                            Loading threat intelligence…
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </article>
          </section>

          <footer className="page-footer">Security monitoring at a glance.</footer>
        </div>
      </section>
      <InvestigationDrawer
        selection={investigationSelection}
        data={investigationData}
        loading={investigationLoading}
        error={investigationError}
        onClose={closeInvestigation}
        onOpenInvestigation={openInvestigation}
      />
    </main>
  )
}

export default App
