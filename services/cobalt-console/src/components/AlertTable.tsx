'use client';

import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import SeverityBadge from './SeverityBadge';
import MitreTag from './MitreTag';
import type { Alert, Severity, AlertStatus } from '@/lib/types';

interface AlertTableProps {
  alerts: Alert[];
  totalCount: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onSeverityFilter: (severity: Severity | null) => void;
  onStatusFilter: (status: AlertStatus | null) => void;
  onSort: (field: string, direction: 'asc' | 'desc') => void;
}

export default function AlertTable({
  alerts,
  totalCount,
  page,
  pageSize,
  onPageChange,
  onSeverityFilter,
  onStatusFilter,
  onSort,
}: AlertTableProps) {
  const [sortField, setSortField] = useState<string>('timestamp');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [statusFilter, setStatusFilter] = useState<AlertStatus | null>(null);

  const totalPages = Math.ceil(totalCount / pageSize);

  const handleSort = (field: string) => {
    const newDirection = sortField === field && sortDirection === 'desc' ? 'asc' : 'desc';
    setSortField(field);
    setSortDirection(newDirection);
    onSort(field, newDirection);
  };

  const handleSeverityFilter = (severity: Severity | null) => {
    setSeverityFilter(severity);
    onSeverityFilter(severity);
  };

  const handleStatusFilter = (status: AlertStatus | null) => {
    setStatusFilter(status);
    onStatusFilter(status);
  };

  const statusOptions: AlertStatus[] = ['NEW', 'INVESTIGATING', 'CONTAINED', 'ERADICATED', 'RESOLVED', 'FALSE_POSITIVE'];
  const severityOptions: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="overflow-hidden rounded-xl border border-dark-700 bg-dark-800">
      <div className="flex items-center gap-4 border-b border-dark-700 p-4">
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Severity:</label>
          <select
            value={severityFilter || ''}
            onChange={(e) => handleSeverityFilter(e.target.value as Severity || null)}
            className="rounded-lg border border-dark-700 bg-dark-900 px-3 py-1.5 text-sm text-white focus:border-cobalt-500 focus:outline-none"
          >
            <option value="">All</option>
            {severityOptions.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Status:</label>
          <select
            value={statusFilter || ''}
            onChange={(e) => handleStatusFilter(e.target.value as AlertStatus || null)}
            className="rounded-lg border border-dark-700 bg-dark-900 px-3 py-1.5 text-sm text-white focus:border-cobalt-500 focus:outline-none"
          >
            <option value="">All</option>
            {statusOptions.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      <table className="w-full">
        <thead>
          <tr className="border-b border-dark-700 text-left text-xs font-medium uppercase text-gray-500">
            <th className="px-4 py-3">
              <button onClick={() => handleSort('severity')} className="flex items-center gap-1">
                Severity
                {sortField === 'severity' && (sortDirection === 'asc' ? ' ↑' : ' ↓')}
              </button>
            </th>
            <th className="px-4 py-3">
              <button onClick={() => handleSort('title')} className="flex items-center gap-1">
                Alert
                {sortField === 'title' && (sortDirection === 'asc' ? ' ↑' : ' ↓')}
              </button>
            </th>
            <th className="px-4 py-3">Source</th>
            <th className="px-4 py-3">MITRE</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">
              <button onClick={() => handleSort('timestamp')} className="flex items-center gap-1">
                Time
                {sortField === 'timestamp' && (sortDirection === 'asc' ? ' ↑' : ' ↓')}
              </button>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-700">
          {alerts.map((alert) => (
            <tr key={alert.id} className="hover:bg-dark-700/50 transition-colors">
              <td className="px-4 py-3">
                <SeverityBadge severity={alert.severity} size="sm" />
              </td>
              <td className="px-4 py-3">
                <div className="text-sm font-medium text-white">{alert.title}</div>
                <div className="text-xs text-gray-500">{alert.id}</div>
              </td>
              <td className="px-4 py-3 text-sm text-gray-400">{alert.source}</td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1">
                  {alert.mitreTechniques.slice(0, 2).map((t) => (
                    <MitreTag key={t} technique={{ id: t, name: t, tactic: '', confidence: 0 }} />
                  ))}
                  {alert.mitreTechniques.length > 2 && (
                    <span className="text-xs text-gray-500">+{alert.mitreTechniques.length - 2}</span>
                  )}
                </div>
              </td>
              <td className="px-4 py-3">
                <span className="inline-flex rounded-full bg-dark-700 px-2 py-1 text-xs text-gray-300">
                  {alert.status}
                </span>
              </td>
              <td className="px-4 py-3 text-sm text-gray-400">
                {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex items-center justify-between border-t border-dark-700 px-4 py-3">
        <div className="text-sm text-gray-400">
          Showing {page * pageSize + 1} to {Math.min((page + 1) * pageSize, totalCount)} of {totalCount}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page === 0}
            className="rounded-lg border border-dark-700 px-3 py-1.5 text-sm text-gray-400 hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Previous
          </button>
          <span className="text-sm text-gray-400">
            Page {page + 1} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages - 1}
            className="rounded-lg border border-dark-700 px-3 py-1.5 text-sm text-gray-400 hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
