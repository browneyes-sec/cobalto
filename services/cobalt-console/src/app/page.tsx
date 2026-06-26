'use client';

import { useEffect, useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import SeverityBadge from '@/components/SeverityBadge';
import { dashboardApi, alertsApi } from '@/lib/api';
import type { DashboardMetrics, Alert, Severity } from '@/lib/types';

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [chartData, setChartData] = useState<{ timestamp: string; count: number }[]>([]);

  useEffect(() => {
    dashboardApi.getMetrics().then(setMetrics);
    dashboardApi.getAlertVolume('24h').then(setChartData);
    alertsApi.list({ limit: 10 }).then((r) => setRecentAlerts(r.alerts));
  }, []);

  const severityCards: { label: string; key: Severity; color: string }[] = [
    { label: 'Critical', key: 'CRITICAL', color: 'text-red-400' },
    { label: 'High', key: 'HIGH', color: 'text-orange-400' },
    { label: 'Medium', key: 'MEDIUM', color: 'text-yellow-400' },
    { label: 'Low', key: 'LOW', color: 'text-blue-400' },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <div className="text-sm font-medium text-gray-400">Active Incidents</div>
          <div className="mt-2 text-3xl font-bold text-white">{metrics?.activeIncidents ?? '—'}</div>
        </div>
        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <div className="text-sm font-medium text-gray-400">Alerts (24h)</div>
          <div className="mt-2 text-3xl font-bold text-white">{metrics?.alertVolume24h ?? '—'}</div>
        </div>
        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <div className="text-sm font-medium text-gray-400">MTTR</div>
          <div className="mt-2 text-3xl font-bold text-white">
            {metrics?.mttrMinutes != null ? `${metrics.mttrMinutes}m` : '—'}
          </div>
        </div>
        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <div className="text-sm font-medium text-gray-400">SLA Compliance</div>
          <div className="mt-2 text-3xl font-bold text-white">
            {metrics?.slaCompliance != null ? `${metrics.slaCompliance}%` : '—'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="col-span-2 rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">Alert Volume (24h)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" />
                <XAxis dataKey="timestamp" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#9ca3af' }}
                />
                <Area type="monotone" dataKey="count" stroke="#0047AB" fill="#0047AB" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">By Severity</h3>
          <div className="space-y-4">
            {severityCards.map((card) => (
              <div key={card.key} className="flex items-center justify-between">
                <div className="text-sm text-gray-300">{card.label}</div>
                <div className={`text-lg font-bold ${card.color}`}>
                  {metrics?.alertsBySeverity?.[card.key] ?? 0}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-dark-700 bg-dark-800">
        <div className="border-b border-dark-700 px-6 py-4">
          <h3 className="text-sm font-medium text-gray-400">Recent Alerts</h3>
        </div>
        <div className="divide-y divide-dark-700">
          {recentAlerts.map((alert) => (
            <div key={alert.id} className="flex items-center justify-between px-6 py-4 hover:bg-dark-700/50 transition-colors">
              <div className="flex items-center gap-4">
                <SeverityBadge severity={alert.severity} size="sm" />
                <div>
                  <div className="text-sm font-medium text-white">{alert.title}</div>
                  <div className="text-xs text-gray-500">{alert.source}</div>
                </div>
              </div>
              <div className="text-sm text-gray-400">
                {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
              </div>
            </div>
          ))}
          {recentAlerts.length === 0 && (
            <div className="px-6 py-8 text-center text-sm text-gray-500">No recent alerts</div>
          )}
        </div>
      </div>
    </div>
  );
}
