'use client';

import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { agentsApi } from '@/lib/api';
import type { AgentPerformance } from '@/lib/types';

export default function AgentsPage() {
  const [performance, setPerformance] = useState<AgentPerformance[]>([]);

  useEffect(() => {
    agentsApi.getPerformance({ period: '7d' }).then(setPerformance);
  }, []);

  const agentNames: Record<string, string> = {
    triage: 'Triage Agent',
    investigation: 'Investigation Agent',
    enrichment: 'Enrichment Agent',
    response: 'Response Agent',
  };

  const latencyData = performance.map((p) => ({
    name: agentNames[p.agentType] || p.agentType,
    avg: p.avgLatency,
    p95: p.p95Latency,
    p99: p.p99Latency,
  }));

  const tokenData = performance.map((p) => ({
    name: agentNames[p.agentType] || p.agentType,
    total: p.totalTokensUsed,
    avg: p.avgTokensPerInvestigation,
  }));

  const accuracyData = performance.map((p) => ({
    name: agentNames[p.agentType] || p.agentType,
    accuracy: p.accuracy * 100,
    falsePositive: p.falsePositiveRate * 100,
  }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {performance.map((p) => (
          <div key={p.agentType} className="rounded-xl border border-dark-700 bg-dark-800 p-6">
            <div className="text-sm font-medium text-gray-400">{agentNames[p.agentType]}</div>
            <div className="mt-2 text-3xl font-bold text-white">{p.totalInvestigations}</div>
            <div className="mt-1 text-xs text-gray-500">investigations</div>
            <div className="mt-3 flex items-center gap-4 text-xs">
              <div>
                <span className="text-gray-500">Latency: </span>
                <span className="text-white">{p.avgLatency.toFixed(0)}ms</span>
              </div>
              <div>
                <span className="text-gray-500">Accuracy: </span>
                <span className="text-green-400">{(p.accuracy * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">Latency Distribution (ms)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={latencyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" />
                <XAxis dataKey="name" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #374151', borderRadius: '8px' }}
                />
                <Bar dataKey="avg" fill="#0047AB" name="Avg" radius={[4, 4, 0, 0]} />
                <Bar dataKey="p95" fill="#1a75ff" name="P95" radius={[4, 4, 0, 0]} />
                <Bar dataKey="p99" fill="#4d94ff" name="P99" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">Token Usage</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tokenData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" />
                <XAxis dataKey="name" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #374151', borderRadius: '8px' }}
                />
                <Bar dataKey="avg" fill="#0047AB" name="Avg Tokens/Investigation" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">Accuracy & False Positive Rate</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={accuracyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" />
                <XAxis dataKey="name" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #374151', borderRadius: '8px' }}
                  formatter={(value: number) => `${value.toFixed(1)}%`}
                />
                <Line type="monotone" dataKey="accuracy" stroke="#22c55e" name="Accuracy" strokeWidth={2} />
                <Line type="monotone" dataKey="falsePositive" stroke="#ef4444" name="FP Rate" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
          <h3 className="mb-4 text-sm font-medium text-gray-400">Total Investigations (7d)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={performance.map((p) => ({
                name: agentNames[p.agentType] || p.agentType,
                count: p.totalInvestigations,
              }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" />
                <XAxis dataKey="name" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #374151', borderRadius: '8px' }}
                />
                <Bar dataKey="count" fill="#0047AB" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
