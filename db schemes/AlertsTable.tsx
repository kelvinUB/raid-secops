import { useMemo, useState } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from '@tanstack/react-table'
import { useNavigate } from 'react-router-dom'
import { useApp } from '../../context/AppContext'
import type { AlertRecord } from '../../types'
import { fmtTs } from '../../lib/utils'
import {
  StatusBadge,
  ConfBadge,
  DeferBadge,
  InvStatusBadge,
  RoleBadge,
} from '../shared/StatusBadge'
import { Button } from '../shared/Button'

interface Props {
  data: AlertRecord[]
}

export function AlertsTable({ data }: Props) {
  const navigate = useNavigate()
  const { setSelectedAlert } = useApp()

  const [globalFilterVal, setGlobalFilterVal] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [siemFilter, setSiemFilter] = useState('ALL')
  const [deferFilter, setDeferFilter] = useState('ALL')

  const filtered = useMemo(() => {
    return data.filter((a) => {
      const q = globalFilterVal.toLowerCase()
      const ms =
        !q ||
        a.sampleId.toLowerCase().includes(q) ||
        a.attackType.toLowerCase().includes(q) ||
        a.mitreTechnique.toLowerCase().includes(q) ||
        a.sourceSiem.toLowerCase().includes(q)
      const mst = statusFilter === 'ALL' || a.status === statusFilter
      const msi = siemFilter === 'ALL' || a.sourceSiem === siemFilter
      const md =
        deferFilter === 'ALL' ||
        (deferFilter === 'YES' && a.deferToHuman) ||
        (deferFilter === 'NO' && !a.deferToHuman)
      return ms && mst && msi && md
    })
  }, [data, globalFilterVal, statusFilter, siemFilter, deferFilter])

  const columns = useMemo<ColumnDef<AlertRecord>[]>(
    () => [
      {
        accessorKey: 'sampleId',
        header: 'Sample ID',
        cell: (i) => (
          <span className="font-mono text-[11px] text-gray-500">{i.getValue<string>()}</span>
        ),
      },
      {
        accessorKey: 'timestamp',
        header: 'Timestamp',
        cell: (i) => (
          <span className="text-[11px] text-gray-400">{fmtTs(i.getValue<string>())}</span>
        ),
      },
      {
        accessorKey: 'sourceSiem',
        header: 'Source SIEM',
        cell: (i) => <span className="text-[12px]">{i.getValue<string>()}</span>,
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: (i) => <StatusBadge status={i.getValue<'ATTACK' | 'NORMAL'>()} />,
      },
      {
        accessorKey: 'confidence',
        header: 'Confidence',
        cell: (i) => <ConfBadge value={i.getValue<number>()} />,
      },
      {
        accessorKey: 'attackType',
        header: 'Attack Type',
        cell: (i) => (
          <span className="text-[11px] text-gray-500">{i.getValue<string>()}</span>
        ),
      },
      {
        accessorKey: 'mitreTechnique',
        header: 'MITRE Technique',
        cell: (i) => (
          <span className="text-[11px] text-gray-400 truncate max-w-[140px] block" title={i.getValue<string>()}>
            {i.getValue<string>()}
          </span>
        ),
      },
      {
        accessorKey: 'deferToHuman',
        header: 'Defer to Human',
        cell: (i) => <DeferBadge value={i.getValue<boolean>()} />,
      },
      {
        accessorKey: 'assignedRole',
        header: 'Assigned Role',
        cell: (i) => <RoleBadge role={i.getValue<'analyst' | 'engineer' | 'grc'>()} />,
      },
      {
        accessorKey: 'investigationStatus',
        header: 'Inv. Status',
        cell: (i) => (
          <InvStatusBadge
            status={i.getValue<'new' | 'under_investigation' | 'escalated' | 'closed'>()}
          />
        ),
      },
      {
        id: 'action',
        header: 'Action',
        cell: ({ row }) => (
          <Button
            variant="primary"
            size="sm"
            onClick={(e) => {
              e.stopPropagation()
              setSelectedAlert(row.original)
              navigate(`/alerts/${row.original.sampleId}`)
            }}
          >
            Open Alert
          </Button>
        ),
      },
    ],
    [navigate, setSelectedAlert]
  )

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  return (
    <div>
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <input
          className="flex-1 min-w-[200px] border border-gray-200 rounded-lg px-3 py-1.5 text-[12px] outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-400 bg-white"
          placeholder="Search sample ID, attack type, MITRE, SIEM…"
          value={globalFilterVal}
          onChange={(e) => setGlobalFilterVal(e.target.value)}
        />
        <select
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-[12px] outline-none bg-white text-gray-600 focus:border-blue-400"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="ALL">All statuses</option>
          <option value="ATTACK">ATTACK only</option>
          <option value="NORMAL">NORMAL only</option>
        </select>
        <select
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-[12px] outline-none bg-white text-gray-600 focus:border-blue-400"
          value={siemFilter}
          onChange={(e) => setSiemFilter(e.target.value)}
        >
          <option value="ALL">All SIEMs</option>
          <option value="Splunk">Splunk</option>
          <option value="Sentinel">Sentinel</option>
        </select>
        <select
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-[12px] outline-none bg-white text-gray-600 focus:border-blue-400"
          value={deferFilter}
          onChange={(e) => setDeferFilter(e.target.value)}
        >
          <option value="ALL">All defer flags</option>
          <option value="YES">Defer: Human Review</option>
          <option value="NO">Defer: Auto</option>
        </select>
        <span className="text-[11px] text-gray-400 whitespace-nowrap">
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                {table.getFlatHeaders().map((header) => (
                  <th
                    key={header.id}
                    className="text-left px-3.5 py-2.5 text-[10px] font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={columns.length}
                    className="text-center py-10 text-[12px] text-gray-400"
                  >
                    No alerts match the current filters.
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-t border-gray-50 hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => {
                      setSelectedAlert(row.original)
                      navigate(`/alerts/${row.original.sampleId}`)
                    }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-3.5 py-2.5 text-[12px] text-gray-700">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
