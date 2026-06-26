'use client';

import { useEffect, useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import Link from 'next/link';
import SeverityBadge from '@/components/SeverityBadge';
import MitreTag from '@/components/MitreTag';
import { incidentsApi } from '@/lib/api';
import type { Incident, Severity, IncidentStatus } from '@/lib/types';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | null>(null);
  const pageSize = 20;

  const fetchIncidents = () => {
    incidentsApi
      .list({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        page,
        limit: pageSize,
      })
      .then((r) => {
        setIncidents(r.incidents);
        setTotalCount(r.total);
      });
  };

  useEffect(() => {
    fetchIncidents();
  }, [page, severityFilter, statusFilter]);

  const statusOptions: IncidentStatus[] = ['OPEN', 'IN_PROGRESS', 'PENDING_APPROVAL', 'CONTAINED', 'CLOSED'];
  const severityOptions: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Incidents</h2>
        <div className="flex items-center gap-3">
          <select
            value={severityFilter || ''}
            onChange={(e) => { setSeverityFilter(e.target.value as Severity || null); setPage(0); }}
            className="rounded-lg border border-dark-700 bg-dark-800 px-3 py-2 text-sm text-white focus:border-cobalt-500 focus:outline-none"
          >
            <option value="">All Severities</option>
            {severityOptions.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={statusFilter || ''}
            onChange={(e) => { setStatusFilter(e.target.value as IncidentStatus || null); setPage(0); }}
            className="rounded-lg border border-dark-700 bg-dark-800 px-3 py-2 text-sm text-white focus:border-cobalt-500 focus:outline-none"
          >
            <option value="">All Statuses</option>
            {statusOptions.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-dark-700 bg-dark-800">
        <table className="w-full">
          <thead>
            <tr className="border-b border-dark-700 text-left text-xs font-medium uppercase text-gray-500">
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Incident</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">MITRE Techniques</th>
              <th className="px-4 py-3">Alerts</th>
              <th className="px-4 py-3">Time Open</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-700">
            {incidents.map((incident) => {
              const timeOpen = Date.now() - new Date(incident.createdAt).getTime();
              const minutesOpen = Math.floor(timeOpen / 60000);
              const isOverdue = minutesOpen > 60;

              return (
                <tr key={incident.id} className="hover:bg-dark-700/50 transition-colors">
                  <td className="px-4 py-3">
                    <SeverityBadge severity={incident.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3">
                    <Link href={`/incidents/${incident.id}`} className="group">
                      <div className="text-sm font-medium text-cobalt-400 group-hover:text-cobalt-300 transition-colors">
                        {incident.title}
                      </div>
                      <div className="text-xs text-gray-500">{incident.id}</div>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex rounded-full bg-dark-700 px-2 py-1 text-xs text-gray-300">
                      {incident.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {incident.mitreMapping.techniques.slice(0, 3).map((t) => (
                        <MitreTag key={t.id} technique={t} />
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">{incident.alerts.length}</td>
                  <td className="px-4 py-3">
                    <span className={`text-sm ${isOverdue ? 'text-red-400 font-medium' : 'text-gray-400'}`}>
                      {formatDistanceToNow(new Date(incident.createdAt))}
                      {isOverdue && ' ⚠'}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {incidents.length === 0 && (
          <div className="px-6 py-12 text-center text-sm text-gray-500">No incidents found</div>
        )}
      </div>

      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-400">
          Showing {page * pageSize + 1} to {Math.min((page + 1) * pageSize, totalCount)} of {totalCount}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="rounded-lg border border-dark-700 px-3 py-1.5 text-sm text-gray-400 hover:bg-dark-700 disabled:opacity-50 transition-colors"
          >
            Previous
          </button>
          <span className="text-sm text-gray-400">
            Page {page + 1} of {Math.max(1, Math.ceil(totalCount / pageSize))}
          </span>
          <button
            onClick={() => setPage(page + 1)}
            disabled={(page + 1) * pageSize >= totalCount}
            className="rounded-lg border border-dark-700 px-3 py-1.5 text-sm text-gray-400 hover:bg-dark-700 disabled:opacity-50 transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
