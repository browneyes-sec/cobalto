'use client';

import { useEffect, useState } from 'react';
import { settingsApi } from '@/lib/api';
import type { NotificationConfig, SLADefinition } from '@/lib/types';

export default function SettingsPage() {
  const [notificationConfig, setNotificationConfig] = useState<NotificationConfig>({
    email: true,
    slack: true,
    escalationDelayMinutes: 15,
  });
  const [slas, setSlas] = useState<SLADefinition[]>([]);
  const [apiKey, setApiKey] = useState('');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    settingsApi.getNotificationConfig().then(setNotificationConfig);
    settingsApi.getSLAs().then(setSlas);
  }, []);

  const handleSaveNotifications = async () => {
    setIsSaving(true);
    await settingsApi.updateNotificationConfig(notificationConfig);
    setIsSaving(false);
  };

  const handleSaveSLAs = async () => {
    setIsSaving(true);
    await settingsApi.updateSLAs(slas);
    setIsSaving(false);
  };

  const handleRegenerateApiKey = async () => {
    const result = await settingsApi.regenerateApiKey();
    setApiKey(result.key);
  };

  const updateSLA = (index: number, field: keyof SLADefinition, value: number) => {
    const updated = [...slas];
    updated[index] = { ...updated[index], [field]: value };
    setSlas(updated);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
        <h3 className="mb-4 text-lg font-semibold text-white">Notification Configuration</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-white">Email Notifications</div>
              <div className="text-xs text-gray-500">Receive alerts via email</div>
            </div>
            <button
              onClick={() => setNotificationConfig({ ...notificationConfig, email: !notificationConfig.email })}
              className={`relative h-6 w-11 rounded-full transition-colors ${
                notificationConfig.email ? 'bg-cobalt-500' : 'bg-dark-700'
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                  notificationConfig.email ? 'translate-x-5' : ''
                }`}
              />
            </button>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-white">Slack Notifications</div>
              <div className="text-xs text-gray-500">Post alerts to Slack channel</div>
            </div>
            <button
              onClick={() => setNotificationConfig({ ...notificationConfig, slack: !notificationConfig.slack })}
              className={`relative h-6 w-11 rounded-full transition-colors ${
                notificationConfig.slack ? 'bg-cobalt-500' : 'bg-dark-700'
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                  notificationConfig.slack ? 'translate-x-5' : ''
                }`}
              />
            </button>
          </div>
          <div>
            <label className="block text-sm font-medium text-white">Escalation Delay (minutes)</label>
            <input
              type="number"
              value={notificationConfig.escalationDelayMinutes}
              onChange={(e) =>
                setNotificationConfig({
                  ...notificationConfig,
                  escalationDelayMinutes: parseInt(e.target.value) || 0,
                })
              }
              className="mt-1 w-32 rounded-lg border border-dark-700 bg-dark-900 px-3 py-2 text-sm text-white focus:border-cobalt-500 focus:outline-none"
            />
          </div>
          <button
            onClick={handleSaveNotifications}
            disabled={isSaving}
            className="rounded-lg bg-cobalt-500 px-4 py-2 text-sm font-medium text-white hover:bg-cobalt-600 disabled:opacity-50 transition-colors"
          >
            {isSaving ? 'Saving...' : 'Save Notification Settings'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
        <h3 className="mb-4 text-lg font-semibold text-white">SLA Thresholds</h3>
        <div className="overflow-hidden rounded-lg border border-dark-700">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-700 bg-dark-900 text-left text-xs font-medium uppercase text-gray-500">
                <th className="px-4 py-3">Priority</th>
                <th className="px-4 py-3">Response (min)</th>
                <th className="px-4 py-3">Containment (min)</th>
                <th className="px-4 py-3">Resolution (min)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700">
              {slas.map((sla, idx) => (
                <tr key={sla.priority}>
                  <td className="px-4 py-3 text-sm font-medium text-white">{sla.priority}</td>
                  <td className="px-4 py-3">
                    <input
                      type="number"
                      value={sla.responseTimeMinutes}
                      onChange={(e) => updateSLA(idx, 'responseTimeMinutes', parseInt(e.target.value) || 0)}
                      className="w-24 rounded border border-dark-700 bg-dark-900 px-2 py-1 text-sm text-white focus:border-cobalt-500 focus:outline-none"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <input
                      type="number"
                      value={sla.containmentTimeMinutes}
                      onChange={(e) => updateSLA(idx, 'containmentTimeMinutes', parseInt(e.target.value) || 0)}
                      className="w-24 rounded border border-dark-700 bg-dark-900 px-2 py-1 text-sm text-white focus:border-cobalt-500 focus:outline-none"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <input
                      type="number"
                      value={sla.resolutionTimeMinutes}
                      onChange={(e) => updateSLA(idx, 'resolutionTimeMinutes', parseInt(e.target.value) || 0)}
                      className="w-24 rounded border border-dark-700 bg-dark-900 px-2 py-1 text-sm text-white focus:border-cobalt-500 focus:outline-none"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <button
          onClick={handleSaveSLAs}
          disabled={isSaving}
          className="mt-4 rounded-lg bg-cobalt-500 px-4 py-2 text-sm font-medium text-white hover:bg-cobalt-600 disabled:opacity-50 transition-colors"
        >
          {isSaving ? 'Saving...' : 'Save SLA Settings'}
        </button>
      </div>

      <div className="rounded-xl border border-dark-700 bg-dark-800 p-6">
        <h3 className="mb-4 text-lg font-semibold text-white">API Keys</h3>
        <div className="space-y-4">
          {apiKey && (
            <div className="rounded-lg bg-dark-900 p-3 font-mono text-sm text-green-400 break-all">
              {apiKey}
            </div>
          )}
          <button
            onClick={handleRegenerateApiKey}
            className="rounded-lg border border-dark-700 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-dark-700 transition-colors"
          >
            Regenerate API Key
          </button>
        </div>
      </div>
    </div>
  );
}
