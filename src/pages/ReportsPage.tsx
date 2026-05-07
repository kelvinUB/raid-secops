import { useState, useEffect, useRef } from 'react'
import { usePageTitle } from '../lib/usePageTitle'
import { fetchAlerts } from '../lib/api'
import type { AlertRow } from '../lib/api'
import { pct } from '../lib/utils'

// ── Helpers ────────────────────────────────────────────────────
function groupBy<T>(arr: T[], key: (item: T) => string): Record<string, T[]> {
  return arr.reduce((acc, item) => {
    const k = key(item)
    acc[k] = acc[k] ? [...acc[k], item] : [item]
    return acc
  }, {} as Record<string, T[]>)
}

const COLORS: Record<string, string> = {
  DoS:            '#DC2626',
  Exploits:       '#D97706',
  Reconnaissance: '#7C3AED',
  Generic:        '#2563EB',
  Backdoor:       '#059669',
  Fuzzers:        '#DB2777',
  Worms:          '#EA580C',
  Shellcode:      '#6B7280',
  Analysis:       '#0891B2',
  Normal:         '#16A34A',
  Unknown:        '#94A3B8',
  '—':            '#CBD5E1',
}

function getColor(key: string) {
  return COLORS[key] || '#64748B'
}

// ── Bar Chart ─────────────────────────────────────────────────
function BarChart({ data, title }: { data: { label: string; value: number; color: string }[]; title: string }) {
  const max = Math.max(...data.map(d => d.value), 1)
  return (
    <div>
      <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{title}</div>
      <div className="flex flex-col gap-2">
        {data.sort((a, b) => b.value - a.value).map(d => (
          <div key={d.label} className="flex items-center gap-2">
            <div className="w-24 text-[11px] text-gray-600 text-right shrink-0 truncate">{d.label}</div>
            <div className="flex-1 bg-gray-100 rounded-full h-5 relative overflow-hidden">
              <div
                className="h-full rounded-full flex items-center justify-end pr-2 transition-all duration-700"
                style={{ width: `${(d.value / max) * 100}%`, backgroundColor: d.color }}
              >
                {d.value > 0 && (
                  <span className="text-[10px] font-bold text-white">{d.value}</span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Donut Chart ───────────────────────────────────────────────
function DonutChart({ data, title }: { data: { label: string; value: number; color: string }[]; title: string }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1
  let cumulative = 0
  const size = 160
  const radius = 60
  const cx = size / 2
  const cy = size / 2

  const slices = data.filter(d => d.value > 0).map(d => {
    const pct = d.value / total
    const startAngle = cumulative * 2 * Math.PI - Math.PI / 2
    cumulative += pct
    const endAngle = cumulative * 2 * Math.PI - Math.PI / 2
    const x1 = cx + radius * Math.cos(startAngle)
    const y1 = cy + radius * Math.sin(startAngle)
    const x2 = cx + radius * Math.cos(endAngle)
    const y2 = cy + radius * Math.sin(endAngle)
    const largeArc = pct > 0.5 ? 1 : 0
    return {
      ...d,
      path: `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`,
      pct,
    }
  })

  return (
    <div>
      <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{title}</div>
      <div className="flex items-center gap-4">
        <svg width={size} height={size} className="shrink-0">
          {slices.map((s, i) => (
            <path key={i} d={s.path} fill={s.color} stroke="white" strokeWidth={2}>
              <title>{s.label}: {s.value} ({(s.pct * 100).toFixed(1)}%)</title>
            </path>
          ))}
          <circle cx={cx} cy={cy} r={36} fill="white" />
          <text x={cx} y={cy - 6} textAnchor="middle" fontSize={18} fontWeight="bold" fill="#1E3A5F">{total}</text>
          <text x={cx} y={cy + 12} textAnchor="middle" fontSize={9} fill="#94A3B8">TOTAL</text>
        </svg>
        <div className="flex flex-col gap-1.5 flex-1 min-w-0">
          {slices.slice(0, 8).map(s => (
            <div key={s.label} className="flex items-center gap-1.5 text-[11px]">
              <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: s.color }} />
              <span className="text-gray-600 truncate flex-1">{s.label}</span>
              <span className="font-semibold text-gray-800">{s.value}</span>
              <span className="text-gray-400">({(s.pct * 100).toFixed(0)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Timeline Chart ────────────────────────────────────────────
function TimelineChart({ alerts, title }: { alerts: AlertRow[]; title: string }) {
  const byDay: Record<string, { attacks: number; normal: number }> = {}
  alerts.forEach(a => {
    const day = a.timestamp ? new Date(a.timestamp).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) : 'Unknown'
    if (!byDay[day]) byDay[day] = { attacks: 0, normal: 0 }
    if (a.status === 'ATTACK') byDay[day].attacks++
    else byDay[day].normal++
  })
  const days = Object.entries(byDay).slice(-14)
  const maxVal = Math.max(...days.flatMap(([, v]) => [v.attacks, v.normal]), 1)

  return (
    <div>
      <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{title}</div>
      {days.length === 0 ? (
        <div className="text-[12px] text-gray-400 py-4 text-center">No data</div>
      ) : (
        <div className="flex items-end gap-1 h-32">
          {days.map(([day, v]) => (
            <div key={day} className="flex-1 flex flex-col items-center gap-0.5">
              <div className="w-full flex flex-col justify-end gap-0.5" style={{ height: 96 }}>
                <div
                  className="w-full rounded-t-sm bg-red-500 transition-all duration-500"
                  style={{ height: `${(v.attacks / maxVal) * 96}px` }}
                  title={`Attacks: ${v.attacks}`}
                />
                <div
                  className="w-full rounded-t-sm bg-green-400 transition-all duration-500"
                  style={{ height: `${(v.normal / maxVal) * 96}px` }}
                  title={`Normal: ${v.normal}`}
                />
              </div>
              <div className="text-[8px] text-gray-400 -rotate-45 origin-top-left translate-y-2 whitespace-nowrap">{day}</div>
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-4 mt-6 text-[10px]">
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-red-500" />Attacks</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-green-400" />Normal</div>
      </div>
    </div>
  )
}

// ── Stat Card ─────────────────────────────────────────────────
function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="bg-white border border-gray-100 rounded-xl p-4 shadow-sm">
      <div className="text-[11px] text-gray-400 font-medium uppercase tracking-wider mb-1">{label}</div>
      <div className="text-[28px] font-bold leading-none" style={{ color }}>{value}</div>
      {sub && <div className="text-[11px] text-gray-400 mt-1">{sub}</div>}
    </div>
  )
}

// ── Download CSV ──────────────────────────────────────────────
function downloadCSV(alerts: AlertRow[]) {
  const headers = ['Sample ID', 'Timestamp', 'Source SIEM', 'Status', 'Confidence', 'Attack Type', 'MITRE Technique', 'Defer to Human', 'Assigned Role', 'Investigation Status']
  const rows = alerts.map(a => [
    a.sampleId,
    a.timestamp ? new Date(a.timestamp).toLocaleString() : '',
    a.sourceSiem,
    a.status,
    pct(a.confidence),
    a.attackType || '—',
    a.mitreTechnique || '—',
    a.deferToHuman ? 'Yes' : 'No',
    a.assignedRole,
    a.investigationStatus,
  ])
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `RAID-SecOps-Report-${new Date().toISOString().split('T')[0]}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Main Page ─────────────────────────────────────────────────
export default function ReportsPage() {
  usePageTitle('Reports')

  const [all, setAll]         = useState<AlertRow[]>([])
  const [loading, setLoading] = useState(true)
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo]   = useState('')

  useEffect(() => {
    fetchAlerts({})
      .then(data => { setAll(data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  // Filter by date range
  const filtered = all.filter(a => {
    if (!a.timestamp) return true
    const d = new Date(a.timestamp)
    if (dateFrom && d < new Date(dateFrom)) return false
    if (dateTo && d > new Date(dateTo + 'T23:59:59')) return false
    return true
  })

  // Derived stats
  const attacks    = filtered.filter(a => a.status === 'ATTACK')
  const normals    = filtered.filter(a => a.status === 'NORMAL')
  const deferred   = filtered.filter(a => a.deferToHuman)
  const avgConf    = filtered.length ? filtered.reduce((s, a) => s + a.confidence, 0) / filtered.length : 0

  // Attack type distribution
  const attackTypes = groupBy(attacks, a => a.attackType || '—')
  const attackTypeData = Object.entries(attackTypes).map(([label, items]) => ({
    label, value: items.length, color: getColor(label)
  }))

  // Status distribution
  const statusData = [
    { label: 'ATTACK', value: attacks.length, color: '#DC2626' },
    { label: 'NORMAL', value: normals.length, color: '#16A34A' },
  ]

  // Role distribution
  const byRole = groupBy(filtered, a => a.assignedRole || 'unknown')
  const roleData = Object.entries(byRole).map(([label, items]) => ({
    label: label === 'analyst' ? 'SOC Analyst' : label === 'engineer' ? 'Security Engineer' : label === 'grc' ? 'CISO / GRC' : label,
    value: items.length,
    color: label === 'analyst' ? '#2563EB' : label === 'engineer' ? '#D97706' : '#7C3AED',
  }))

  // MITRE distribution
  const byMitre = groupBy(attacks.filter(a => a.mitreTechnique && a.mitreTechnique !== '—'), a => a.mitreTechnique!)
  const mitreData = Object.entries(byMitre).map(([label, items]) => ({
    label: label.split('–')[0].trim(),
    value: items.length,
    color: getColor(label.split('–')[1]?.trim() || label),
  }))

  // SIEM source
  const bySiem = groupBy(filtered, a => a.sourceSiem || 'Unknown')
  const siemData = Object.entries(bySiem).map(([label, items]) => ({
    label, value: items.length, color: getColor(label),
  }))

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[13px] text-gray-400">Loading report data...</div>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-[16px] font-bold text-gray-900">Security Operations Report</h1>
          <p className="text-[12px] text-gray-400 mt-0.5">
            {filtered.length.toLocaleString()} alerts
            {(dateFrom || dateTo) ? ` filtered` : ' total'} · Generated {new Date().toLocaleString()}
          </p>
        </div>
        <button
          onClick={() => downloadCSV(filtered)}
          className="flex items-center gap-2 px-4 py-2 bg-[#1E3A5F] text-white text-[12px] font-medium rounded-lg hover:bg-[#2851A3] transition-colors"
        >
          ↓ Download CSV
        </button>
      </div>

      {/* Date filter */}
      <div className="bg-white border border-gray-100 rounded-xl px-4 py-3 shadow-sm flex items-center gap-4 flex-wrap">
        <span className="text-[12px] font-semibold text-gray-600">Filter by date:</span>
        <div className="flex items-center gap-2">
          <label className="text-[11px] text-gray-400">From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
            className="border border-gray-200 rounded-lg px-2.5 py-1.5 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400"
          />
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[11px] text-gray-400">To</label>
          <input
            type="date"
            value={dateTo}
            onChange={e => setDateTo(e.target.value)}
            className="border border-gray-200 rounded-lg px-2.5 py-1.5 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400"
          />
        </div>
        {(dateFrom || dateTo) && (
          <button
            onClick={() => { setDateFrom(''); setDateTo('') }}
            className="text-[11px] text-blue-500 hover:text-blue-700 underline"
          >
            Clear
          </button>
        )}
        <span className="text-[11px] text-gray-400 ml-auto">{filtered.length.toLocaleString()} results</span>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Total Alerts"       value={filtered.length.toLocaleString()} sub="in selected range"         color="#1E3A5F" />
        <StatCard label="Predicted Attacks"  value={attacks.length.toLocaleString()}  sub={pct(attacks.length / (filtered.length || 1))} color="#DC2626" />
        <StatCard label="Human Review"       value={deferred.length.toLocaleString()} sub="deferred to human"         color="#D97706" />
        <StatCard label="Avg Confidence"     value={pct(avgConf)}                     sub="hybrid ML score"           color="#2563EB" />
      </div>

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <DonutChart data={statusData} title="Attack vs Normal Distribution" />
        </div>
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <DonutChart data={attackTypeData.slice(0, 8)} title="Attack Type Breakdown" />
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
        <TimelineChart alerts={filtered} title="Alerts Over Time (Last 14 Days)" />
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <BarChart data={attackTypeData} title="Attack Types" />
        </div>
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <BarChart data={roleData} title="Assigned Role" />
        </div>
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <BarChart data={siemData} title="SIEM Source" />
        </div>
      </div>

      {/* MITRE */}
      {mitreData.length > 0 && (
        <div className="bg-white border border-gray-100 rounded-xl p-5 shadow-sm">
          <BarChart data={mitreData} title="MITRE ATT&CK Technique Distribution" />
        </div>
      )}

      {/* Footer */}
      <div className="text-[11px] text-gray-400 text-center pb-2">
        RAID-SecOps · ML-Scored Security Operations Report · {new Date().toLocaleDateString()}
      </div>
    </div>
  )
}
