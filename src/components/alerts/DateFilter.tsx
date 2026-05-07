// ── DateFilter.tsx ────────────────────────────────────────────
// Drop this component into src/components/alerts/DateFilter.tsx
// Then import and use in AlertsQueuePage.tsx

interface DateFilterProps {
  dateFrom: string
  dateTo:   string
  onFrom:   (v: string) => void
  onTo:     (v: string) => void
  onClear:  () => void
  count:    number
}

export function DateFilter({ dateFrom, dateTo, onFrom, onTo, onClear, count }: DateFilterProps) {
  const active = !!(dateFrom || dateTo)
  return (
    <div className="flex items-center gap-3 flex-wrap">
      <span className="text-[11px] font-semibold text-gray-500">Date:</span>
      <input
        type="date"
        value={dateFrom}
        onChange={e => onFrom(e.target.value)}
        className="border border-gray-200 rounded-lg px-2.5 py-1.5 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400 bg-white"
      />
      <span className="text-[11px] text-gray-400">to</span>
      <input
        type="date"
        value={dateTo}
        onChange={e => onTo(e.target.value)}
        className="border border-gray-200 rounded-lg px-2.5 py-1.5 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400 bg-white"
      />
      {active && (
        <button
          onClick={onClear}
          className="text-[11px] text-blue-500 hover:text-blue-700 underline"
        >
          Clear
        </button>
      )}
      {active && (
        <span className="text-[11px] text-gray-400">{count.toLocaleString()} results</span>
      )}
    </div>
  )
}
