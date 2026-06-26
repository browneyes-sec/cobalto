import axios from 'axios';
import type {
  Alert,
  Incident,
  AgentPerformance,
  DashboardMetrics,
  NotificationConfig,
  SLADefinition,
} from './types';

const apiClient = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export const dashboardApi = {
  getMetrics: () =>
    apiClient.get<DashboardMetrics>('/backend/metrics').then((r) => r.data),

  getAlertVolume: (period: string = '24h') =>
    apiClient.get<{ timestamp: string; count: number }[]>('/backend/alerts/volume', {
      params: { period },
    }).then((r) => r.data),
};

export const alertsApi = {
  list: (params?: {
    severity?: string;
    status?: string;
    source?: string;
    page?: number;
    limit?: number;
  }) =>
    apiClient.get<{ alerts: Alert[]; total: number }>('/backend/alerts', { params }).then((r) => r.data),

  getById: (id: string) =>
    apiClient.get<Alert>(`/backend/alerts/${id}`).then((r) => r.data),

  updateStatus: (id: string, status: string) =>
    apiClient.patch<Alert>(`/backend/alerts/${id}`, { status }).then((r) => r.data),
};

export const incidentsApi = {
  list: (params?: {
    severity?: string;
    status?: string;
    page?: number;
    limit?: number;
  }) =>
    apiClient.get<{ incidents: Incident[]; total: number }>('/backend/incidents', { params }).then((r) => r.data),

  getById: (id: string) =>
    apiClient.get<Incident>(`/backend/incidents/${id}`).then((r) => r.data),

  approveAction: (incidentId: string, actionId: string, notes: string) =>
    apiClient.post(`/backend/incidents/${incidentId}/actions/${actionId}/approve`, { notes }).then((r) => r.data),

  rejectAction: (incidentId: string, actionId: string, notes: string) =>
    apiClient.post(`/backend/incidents/${incidentId}/actions/${actionId}/reject`, { notes }).then((r) => r.data),
};

export const agentsApi = {
  getPerformance: (params?: { period?: string }) =>
    apiClient.get<AgentPerformance[]>('/backend/agents/performance', { params }).then((r) => r.data),

  getInvestigationTrace: (incidentId: string) =>
    apiClient.get(`/langgraph/investigations/${incidentId}/trace`).then((r) => r.data),
};

export const settingsApi = {
  getNotificationConfig: () =>
    apiClient.get<NotificationConfig>('/backend/settings/notifications').then((r) => r.data),

  updateNotificationConfig: (config: NotificationConfig) =>
    apiClient.put('/backend/settings/notifications', config).then((r) => r.data),

  getSLAs: () =>
    apiClient.get<SLADefinition[]>('/backend/settings/slas').then((r) => r.data),

  updateSLAs: (slas: SLADefinition[]) =>
    apiClient.put('/backend/settings/slas', slas).then((r) => r.data),

  regenerateApiKey: () =>
    apiClient.post<{ key: string; createdAt: string }>('/backend/settings/api-keys').then((r) => r.data),
};
