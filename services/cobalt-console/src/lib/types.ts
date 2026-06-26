export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'ERADICATED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type IncidentStatus = 'OPEN' | 'IN_PROGRESS' | 'PENDING_APPROVAL' | 'CONTAINED' | 'CLOSED';

export type AgentType = 'triage' | 'investigation' | 'enrichment' | 'response';

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  source: string;
  timestamp: string;
  mitreTechniques: string[];
  assignee?: string;
  customerId: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  alerts: Alert[];
  mitreMapping: MitreMapping;
  timeline: TimelineEvent[];
  responseActions: ResponseAction[];
  createdAt: string;
  updatedAt: string;
  customerId: string;
}

export interface MitreMapping {
  tactic: string;
  techniques: MitreTechnique[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  confidence: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'alert' | 'investigation' | 'action' | 'note' | 'escalation';
  agent?: string;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface ResponseAction {
  id: string;
  type: string;
  description: string;
  status: 'PENDING' | 'APPROVED' | 'EXECUTED' | 'REJECTED' | 'FAILED';
  requestedBy: string;
  approvedBy?: string;
  approvalNotes?: string;
  executedAt?: string;
  result?: string;
}

export interface SOCAgentState {
  incidentId: string;
  alerts: Alert[];
  enrichedData: EnrichedData;
  investigationTrace: InvestigationStep[];
  recommendedActions: ResponseAction[];
  approvalRequired: boolean;
  severity: Severity;
  mitreMapping: MitreMapping;
}

export interface EnrichedData {
  threatIntel: ThreatIntel;
  assetInfo: AssetInfo;
  userData?: UserInfo;
  iocMatches: IOCMatch[];
}

export interface ThreatIntel {
  score: number;
  tags: string[];
  source: string;
  lastSeen: string;
}

export interface AssetInfo {
  hostname: string;
  ipAddress: string;
  os: string;
  criticality: 'HIGH' | 'MEDIUM' | 'LOW';
  owner?: string;
}

export interface UserInfo {
  userId: string;
  displayName: string;
  department: string;
  riskScore: number;
}

export interface IOCMatch {
  indicator: string;
  type: string;
  confidence: number;
  source: string;
}

export interface InvestigationStep {
  id: string;
  agent: AgentType;
  action: string;
  input: string;
  output: string;
  timestamp: string;
  duration: number;
  status: 'running' | 'completed' | 'failed';
}

export interface AgentPerformance {
  agentType: AgentType;
  totalInvestigations: number;
  avgLatency: number;
  p95Latency: number;
  p99Latency: number;
  totalTokensUsed: number;
  avgTokensPerInvestigation: number;
  accuracy: number;
  falsePositiveRate: number;
  period: string;
}

export interface SLADefinition {
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  responseTimeMinutes: number;
  containmentTimeMinutes: number;
  resolutionTimeMinutes: number;
}

export interface SLAStatus {
  alertId: string;
  priority: string;
  responseTimeRemaining: number;
  containmentTimeRemaining: number;
  breached: boolean;
  breachType?: 'response' | 'containment' | 'resolution';
}

export interface ShiftSchedule {
  id: string;
  analystId: string;
  analystName: string;
  startDate: string;
  endDate: string;
  shift: 'day' | 'evening' | 'night';
  handoverNotes?: string;
}

export interface NotificationConfig {
  email: boolean;
  slack: boolean;
  webhook?: string;
  slackChannel?: string;
  escalationDelayMinutes: number;
}

export interface DashboardMetrics {
  activeIncidents: number;
  alertVolume24h: number;
  mttrMinutes: number;
  slaCompliance: number;
  alertsBySource: Record<string, number>;
  alertsBySeverity: Record<Severity, number>;
}
