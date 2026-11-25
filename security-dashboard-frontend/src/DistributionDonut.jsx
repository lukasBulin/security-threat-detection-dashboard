import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

function formatCategoryLabel(value) {
  return value
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function DistributionDonut({ data, colors, unit, loading }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)

  if (data.length === 0) {
    return (
      <div className="trend-empty">
        {loading ? 'Loading chart data…' : `No ${unit.toLowerCase()} data available.`}
      </div>
    )
  }

  return (
    <div className="trend-chart-area">
      <div className="trend-chart-center" aria-hidden="true">
        <strong>{total.toLocaleString()}</strong>
        <span>{unit}</span>
      </div>
      <div
        className="trend-chart"
        role="img"
        aria-label={`${unit} distribution donut chart`}
      >
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="44%"
              innerRadius={58}
              outerRadius={88}
              paddingAngle={2}
              stroke="#fff"
              strokeWidth={3}
            >
              {data.map((item) => (
                <Cell
                  key={item.name}
                  fill={colors[item.name.trim().toUpperCase()] || '#8293ad'}
                />
              ))}
            </Pie>
            <Tooltip
              formatter={(value, name) => {
                const count = Number(value)
                const percentage = total ? Math.round((count / total) * 100) : 0
                return [
                  `${count.toLocaleString()} (${percentage}%)`,
                  formatCategoryLabel(String(name)),
                ]
              }}
            />
            <Legend
              verticalAlign="bottom"
              height={42}
              iconType="circle"
              iconSize={7}
              formatter={formatCategoryLabel}
              wrapperStyle={{ fontSize: '10px' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default DistributionDonut
