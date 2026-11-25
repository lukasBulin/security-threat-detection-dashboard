import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const seriesColors = {
  high: '#e28b45',
  critical: '#e35b61',
}

function formatTick(value, range) {
  const date = new Date(value)
  const options = range === '24h'
    ? { hour: 'numeric' }
    : { month: 'short', day: 'numeric' }

  return new Intl.DateTimeFormat(undefined, options).format(date)
}

function formatTooltipDate(value, range) {
  const date = new Date(value)
  const options = range === '24h'
    ? { month: 'short', day: 'numeric', hour: 'numeric' }
    : { weekday: 'short', month: 'short', day: 'numeric' }

  return new Intl.DateTimeFormat(undefined, options).format(date)
}

function AlertTimelineChart({ data, range, loading }) {
  if (loading && data.length === 0) {
    return <div className="timeline-empty">Loading alert activity…</div>
  }

  if (data.length === 0) {
    return <div className="timeline-empty">No alert activity for this range.</div>
  }

  return (
    <div className="timeline-chart-wrap">
      {loading && <span className="timeline-loading">Updating…</span>}
      <div
        className="timeline-chart"
        role="img"
        aria-label={`High and critical alert counts over the last ${range}`}
      >
        <ResponsiveContainer width="100%" height={290}>
          <LineChart
            data={data}
            margin={{ top: 16, right: 20, bottom: 4, left: -12 }}
          >
            <CartesianGrid
              stroke="#edf0f4"
              strokeDasharray="3 5"
              vertical={false}
            />
            <XAxis
              dataKey="timestamp"
              type="number"
              scale="time"
              domain={['dataMin', 'dataMax']}
              tickFormatter={(value) => formatTick(value, range)}
              tick={{ fill: '#929cac', fontSize: 9 }}
              tickLine={false}
              axisLine={{ stroke: '#e8ecf2' }}
              tickCount={range === '24h' ? 8 : range === '7d' ? 7 : 8}
              minTickGap={24}
            />
            <YAxis
              allowDecimals={false}
              domain={[0, 'auto']}
              tick={{ fill: '#929cac', fontSize: 9 }}
              tickLine={false}
              axisLine={false}
              width={38}
            />
            <Tooltip
              labelFormatter={(value) => formatTooltipDate(value, range)}
              formatter={(value, name) => [
                `${Number(value).toLocaleString()} alerts`,
                String(name).toUpperCase(),
              ]}
              contentStyle={{
                border: '1px solid #e7ebf1',
                borderRadius: 7,
                boxShadow: '0 5px 16px rgb(24 39 75 / 10%)',
                fontSize: 11,
              }}
            />
            <Legend
              verticalAlign="top"
              align="right"
              height={30}
              iconType="circle"
              iconSize={7}
              formatter={(value) => String(value).toUpperCase()}
              wrapperStyle={{ color: '#687487', fontSize: 10 }}
            />
            <Line
              type="monotone"
              dataKey="high"
              name="High"
              stroke={seriesColors.high}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              connectNulls
            />
            <Line
              type="monotone"
              dataKey="critical"
              name="Critical"
              stroke={seriesColors.critical}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              connectNulls
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default AlertTimelineChart
