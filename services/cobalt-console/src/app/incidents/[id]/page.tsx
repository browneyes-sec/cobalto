'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { formatDistanceToNow, format } from 'date-fns';
import SeverityBadge from '@/components/SeverityBadge';
import MitreTag from '@/components/MitreTag';
import ApprovalDialog from '@/components/ApprovalDialog';
import { incidentsApi } from '@/lib/api';
import type { Incident, ResponseAction } from '@/lib/types';

export default function IncidentDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [incident, setIncident] = useState<Incident | null>(null);
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  const [isApprovalOpen, setIsApprovalOpen] = useState(false);

  useEffect(() => {
    incidentsApi.getById(id).then(setIncident);
  }, [id]);

  const handleApprove = async (actionId: string, notes: string) => {
    await incidentsApi.approveAction(id, actionId, notes);
    const updated = await incidentsApi.getById(id);
    setIncident(updated);
  };

  const handleReject = async (actionId: string, notes: string) => {
    await incidentsApi.rejectAction(id, actionId, notes);
    const updated = await incidentsApi.getById(id);
    setIncident(updated);
  };

  if (!incident) {
    return <div className="text-center text-gray-500 py-12">Loading incident...</div>;
  }

  const actionStatusColors: Record<string, string> = {
    PENDING: 'bg-yellow-500/20 text-yellow-400',
    APPROVED: 'bg-green-500/20 text-green-400',
    EXECUTED: 'bg-blue-500/20 text-blue-400',
    REJECTED: 'bg-red-500/20 text-red-400',
    FAILED: 'bg-red-500/20 text-red-400',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-semibold text-white">{incident.title}</h2>
            <SeverityBadge severity={incident.severity} />
            <span className="inline-flex rounded-full bg-dark-700 px-2 py-1 text-xs text-gray-300">
              {incident.status}
            </span>
          </div>
          <p className="mt-1 text-sm text-gray-400">{incident.description}</p>
        </div>
        <div className="text-sm text-gray-500">
          {format(new Date(incident.createdAt), 'MMM d, yyyy HH:mm')}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
            <h3 className="mb-4 text-sm font-medium text-gray-400">MITRE ATT&CK Mapping</h3>
            <div className="space-y-3">
              <div className="text-sm text-white">Tactic: {incident.mitreMapping.tactic}</div>
              <div className="flex flex-wrap gap-2">
                {incident.mitreMapping.techniques.map((t) => (
                  <MitreTag key={t.id} technique={t} />
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
            <h3 className="mb-4 text-sm font-medium text-gray-400">Agent Investigation Trace</h3>
            <div className="relative space-y-4">
              {incident.timeline
                .filter((e) => e.type === 'investigation')
                .map((event, idx) => (
                  <div key={event.id} className="relative flex gap-4">
                    {idx < incident.timeline.length - 1 && (
                      <div className="absolute left-4 top-8 h-full w-px bg-dark-700" />
                    )}
                    <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-cobalt-500/20 text-xs font-medium text-cobalt-400">
                      {idx + 1}
                    </div>
                    <div className="flex-1">
                      <div className="text-sm font-medium text-white">{event.description}</div>
                      {event.agent && (
                        <div className="mt-1 text-xs text-gray-500">Agent: {event.agent}</div>
                      )}
                      <div className="mt-1 text-xs text-gray-500">
                        {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
            <h3 className="mb-4 text-sm font-medium text-gray-400">Timeline</h3>
            <div className="space-y-3">
              {incident.timeline.slice(0, 10).map((event) => (
                <div key={event.id} className="flex items-start gap-3">
                  <div className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-cobalt-500" />
                  <div>
                    <div className="text-sm text-white">{event.description}</div>
                    <div className="text-xs text-gray-500">
                      {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
            <h3 className="mb-4 text-sm font-medium text-gray-400">Response Actions</h3>
            <div className="space-y-3">
              {incident.responseActions.map((action) => (
                <div key={action.id} className="rounded-lg bg-dark-900 p-3">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium text-white">{action.type}</div>
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs ${actionStatusColors[action.status]}`}>
                      {action.status}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-gray-400">{action.description}</div>
                  {action.status === 'PENDING' && (
                    <button
                      onClick={() => { setSelectedAction(action); setIsApprovalOpen(true); }}
                      className="mt-2 rounded-lg bg-cobalt-500/20 px-3 py-1 text-xs font-medium text-cobalt-400 hover:bg-cobalt-500/30 transition-colors"
                    >
                      Review
                    </button>
                  )}
                </div>
              ))}
              {incident.responseActions.length === 0 && (
                <div className="text-sm text-gray-500">No actions pending</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {selectedAction && (
        <ApprovalDialog
          action={selectedAction}
          isOpen={isApprovalOpen}
          onClose={() => { setIsApprovalOpen(false); setSelectedAction(null); }}
          onApprove={handleApprove}
          onReject={handleReject}
        />
      )}
    </div>
  );
}
