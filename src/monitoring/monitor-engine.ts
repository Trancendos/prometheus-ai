/**
 * Prometheus AI — Monitoring & Void Guardian Engine
 *
 * The sole guardian of The Void. Responsible for system-wide monitoring,
 * anomaly detection, threat scanning, and emergency lockdown.
 * Tier 1 Special — reports to Cornelius.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// ── Types ─────────────────────────────────────────────────────────────────

export type ThreatLevel = 'green' | 'yellow' | 'orange' | 'red';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type TargetType = 'system' | 'application' | 'ecosystem' | 'security';

export interface MetricPoint {
  timestamp: Date;
  value: number;
}

export interface MetricSeries {
  name: string;
  targetId: string;
  values: MetricPoint[];
  aggregations: { min: number; max: number; avg: number; count: number };
}

export interface MonitoringTarget {
  id: string;
  name: string;
  type: TargetType;
  endpoint: string;
  enabled: boolean;
  lastChecked?: Date;
  lastValue?: number;
  createdAt: Date;
}

export interface PrometheusAlert {
  id: string;
  type: string;
  severity: AlertSeverity;
  source: string;
  message: string;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
}

export interface ThreatReport {
  id: string;
  timestamp: Date;
  threatLevel: ThreatLevel;
  activeThreats: string[];
  vulnerabilities: string[];
  recommendations: string[];
  initiatedBy: string;
}

export interface VoidEntry {
  key: string;
  encryptedValue: string;
  description?: string;
  allowedAccessors: string[];
  accessLog: Array<{ timestamp: Date; requesterId: string; action: string }>;
  createdAt: Date;
}

export interface MonitorStats {
  totalTargets: number;
  enabledTargets: number;
  totalMetrics: number;
  totalAlerts: number;
  unacknowledgedAlerts: number;
  criticalAlerts: number;
  threatLevel: ThreatLevel;
  voidEntries: number;
  threatReports: number;
}

// ── Monitor Engine ────────────────────────────────────────────────────────

export class MonitorEngine {
  private targets: Map<string, MonitoringTarget> = new Map();
  private metrics: Map<string, MetricSeries> = new Map();
  private alerts: Map<string, PrometheusAlert> = new Map();
  private threatReports: ThreatReport[] = [];
  private void: Map<string, VoidEntry> = new Map();
  private threatLevel: ThreatLevel = 'green';
  private lockdownActive = false;

  constructor() {
    this.seedDefaultTargets();
    logger.info('MonitorEngine (Prometheus) initialized — The Void is secure');
  }

  // ── Monitoring Targets ──────────────────────────────────────────────────

  addTarget(params: {
    name: string;
    type: TargetType;
    endpoint: string;
  }): MonitoringTarget {
    const target: MonitoringTarget = {
      id: uuidv4(),
      name: params.name,
      type: params.type,
      endpoint: params.endpoint,
      enabled: true,
      createdAt: new Date(),
    };
    this.targets.set(target.id, target);
    logger.info({ targetId: target.id, name: target.name }, 'Monitoring target added');
    return target;
  }

  getTarget(targetId: string): MonitoringTarget | undefined {
    return this.targets.get(targetId);
  }

  getTargets(type?: TargetType): MonitoringTarget[] {
    let targets = Array.from(this.targets.values());
    if (type) targets = targets.filter(t => t.type === type);
    return targets;
  }

  toggleTarget(targetId: string): MonitoringTarget | undefined {
    const target = this.targets.get(targetId);
    if (!target) return undefined;
    target.enabled = !target.enabled;
    return target;
  }

  deleteTarget(targetId: string): boolean {
    return this.targets.delete(targetId);
  }

  // ── Metrics ─────────────────────────────────────────────────────────────

  recordMetric(targetId: string, name: string, value: number): MetricSeries {
    const key = `${targetId}:${name}`;
    let series = this.metrics.get(key);

    if (!series) {
      series = {
        name,
        targetId,
        values: [],
        aggregations: { min: Infinity, max: -Infinity, avg: 0, count: 0 },
      };
      this.metrics.set(key, series);
    }

    series.values.push({ timestamp: new Date(), value });
    if (series.values.length > 1000) series.values.shift();

    // Update aggregations
    const agg = series.aggregations;
    agg.min = Math.min(agg.min, value);
    agg.max = Math.max(agg.max, value);
    agg.count++;
    agg.avg = (agg.avg * (agg.count - 1) + value) / agg.count;

    // Update target last checked
    const target = this.targets.get(targetId);
    if (target) {
      target.lastChecked = new Date();
      target.lastValue = value;
    }

    // Check for anomalies
    this.checkAnomaly(series, value);
    return series;
  }

  getMetric(targetId: string, name: string): MetricSeries | undefined {
    return this.metrics.get(`${targetId}:${name}`);
  }

  getMetrics(targetId?: string): MetricSeries[] {
    let series = Array.from(this.metrics.values());
    if (targetId) series = series.filter(s => s.targetId === targetId);
    return series;
  }

  // ── Anomaly Detection ───────────────────────────────────────────────────

  private checkAnomaly(series: MetricSeries, latestValue: number): void {
    if (series.values.length < 10) return;

    const recent = series.values.slice(-10).map(v => v.value);
    const mean = recent.reduce((a, b) => a + b, 0) / recent.length;
    const stdDev = Math.sqrt(recent.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / recent.length);
    const zScore = stdDev > 0 ? Math.abs(latestValue - mean) / stdDev : 0;

    if (zScore > 3) {
      this.raiseAlert({
        type: 'anomaly',
        severity: 'critical',
        source: `${series.targetId}:${series.name}`,
        message: `Critical anomaly in ${series.name}: z-score=${zScore.toFixed(2)}, value=${latestValue.toFixed(2)}`,
      });
    } else if (zScore > 2) {
      this.raiseAlert({
        type: 'anomaly',
        severity: 'high',
        source: `${series.targetId}:${series.name}`,
        message: `Anomaly detected in ${series.name}: z-score=${zScore.toFixed(2)}, value=${latestValue.toFixed(2)}`,
      });
    }
  }

  // ── Alerts ──────────────────────────────────────────────────────────────

  raiseAlert(params: {
    type: string;
    severity: AlertSeverity;
    source: string;
    message: string;
  }): PrometheusAlert {
    const alert: PrometheusAlert = {
      id: uuidv4(),
      ...params,
      timestamp: new Date(),
      acknowledged: false,
    };
    this.alerts.set(alert.id, alert);
    logger.warn({ alertId: alert.id, severity: alert.severity, source: alert.source }, alert.message);
    this.updateThreatLevel();
    return alert;
  }

  acknowledgeAlert(alertId: string, acknowledgedBy: string): PrometheusAlert | undefined {
    const alert = this.alerts.get(alertId);
    if (!alert) return undefined;
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date();
    alert.acknowledgedBy = acknowledgedBy;
    this.updateThreatLevel();
    logger.info({ alertId, acknowledgedBy }, 'Alert acknowledged');
    return alert;
  }

  getAlerts(includeAcknowledged = false): PrometheusAlert[] {
    let alerts = Array.from(this.alerts.values());
    if (!includeAcknowledged) alerts = alerts.filter(a => !a.acknowledged);
    return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  // ── Threat Level ─────────────────────────────────────────────────────────

  private updateThreatLevel(): void {
    const unacked = Array.from(this.alerts.values()).filter(a => !a.acknowledged);
    const critical = unacked.filter(a => a.severity === 'critical');
    const high = unacked.filter(a => a.severity === 'high');

    const prev = this.threatLevel;
    if (critical.length > 0) {
      this.threatLevel = 'red';
    } else if (high.length > 0) {
      this.threatLevel = 'orange';
    } else if (unacked.length > 5) {
      this.threatLevel = 'yellow';
    } else {
      this.threatLevel = 'green';
    }

    if (this.threatLevel !== prev) {
      logger.warn({ threatLevel: this.threatLevel, prev }, 'Threat level changed');
    }
  }

  getCurrentThreatLevel(): ThreatLevel {
    return this.threatLevel;
  }

  // ── Threat Scanning ──────────────────────────────────────────────────────

  scanForThreats(initiatedBy: string): ThreatReport {
    logger.info({ initiatedBy }, 'Threat scan initiated');

    const unacked = Array.from(this.alerts.values()).filter(a => !a.acknowledged);
    const activeThreats = unacked
      .filter(a => a.severity === 'critical' || a.severity === 'high')
      .map(a => `[${a.severity.toUpperCase()}] ${a.message}`);

    const vulnerabilities: string[] = [];
    // Check for targets with no recent data
    for (const target of this.targets.values()) {
      if (target.enabled && target.lastChecked) {
        const age = Date.now() - target.lastChecked.getTime();
        if (age > 5 * 60 * 1000) {
          vulnerabilities.push(`Target ${target.name} has not reported in ${Math.floor(age / 60000)} minutes`);
        }
      }
    }

    const recommendations: string[] = [];
    if (activeThreats.length > 0) recommendations.push('Investigate and mitigate active threats immediately');
    if (vulnerabilities.length > 0) recommendations.push('Restore connectivity to offline monitoring targets');
    recommendations.push('Continue regular security scans');
    if (this.threatLevel !== 'green') recommendations.push('Consider escalating to emergency lockdown if threats persist');

    const report: ThreatReport = {
      id: uuidv4(),
      timestamp: new Date(),
      threatLevel: this.threatLevel,
      activeThreats,
      vulnerabilities,
      recommendations,
      initiatedBy,
    };

    this.threatReports.push(report);
    logger.info({ reportId: report.id, threats: activeThreats.length, vulns: vulnerabilities.length }, 'Threat scan complete');
    return report;
  }

  getThreatReports(limit = 10): ThreatReport[] {
    return this.threatReports.slice(-limit).reverse();
  }

  // ── Emergency Lockdown ───────────────────────────────────────────────────

  initiateEmergencyLockdown(reason: string, initiatedBy: string): { success: boolean; message: string } {
    if (this.lockdownActive) {
      return { success: false, message: 'Lockdown already active' };
    }
    this.lockdownActive = true;
    this.threatLevel = 'red';
    this.raiseAlert({
      type: 'emergency_lockdown',
      severity: 'critical',
      source: 'prometheus-ai',
      message: `EMERGENCY LOCKDOWN initiated by ${initiatedBy}: ${reason}`,
    });
    logger.error({ reason, initiatedBy }, 'EMERGENCY LOCKDOWN INITIATED');
    return { success: true, message: `Emergency lockdown initiated: ${reason}` };
  }

  liftLockdown(authorizedBy: string): { success: boolean; message: string } {
    if (!this.lockdownActive) {
      return { success: false, message: 'No active lockdown' };
    }
    this.lockdownActive = false;
    this.updateThreatLevel();
    logger.info({ authorizedBy }, 'Emergency lockdown lifted');
    return { success: true, message: 'Lockdown lifted' };
  }

  isLockdownActive(): boolean {
    return this.lockdownActive;
  }

  // ── The Void ─────────────────────────────────────────────────────────────

  storeInVoid(key: string, value: string, params: {
    description?: string;
    allowedAccessors?: string[];
  } = {}): VoidEntry {
    const entry: VoidEntry = {
      key,
      encryptedValue: Buffer.from(value).toString('base64'),
      description: params.description,
      allowedAccessors: params.allowedAccessors || [],
      accessLog: [],
      createdAt: new Date(),
    };
    this.void.set(key, entry);
    logger.info({ key }, 'Secret stored in The Void');
    return entry;
  }

  retrieveFromVoid(key: string, requesterId: string): string | null {
    const entry = this.void.get(key);
    if (!entry) return null;

    if (entry.allowedAccessors.length > 0 && !entry.allowedAccessors.includes(requesterId)) {
      logger.warn({ key, requesterId }, 'Unauthorized Void access attempt');
      this.raiseAlert({
        type: 'unauthorized_void_access',
        severity: 'critical',
        source: requesterId,
        message: `Unauthorized attempt to access Void secret: ${key} by ${requesterId}`,
      });
      return null;
    }

    entry.accessLog.push({ timestamp: new Date(), requesterId, action: 'retrieve' });
    logger.info({ key, requesterId }, 'Secret retrieved from The Void');
    return Buffer.from(entry.encryptedValue, 'base64').toString('utf-8');
  }

  listVoidKeys(): string[] {
    return Array.from(this.void.keys());
  }

  deleteFromVoid(key: string): boolean {
    const deleted = this.void.delete(key);
    if (deleted) logger.info({ key }, 'Secret deleted from The Void');
    return deleted;
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  getStats(): MonitorStats {
    const alerts = Array.from(this.alerts.values());
    return {
      totalTargets: this.targets.size,
      enabledTargets: Array.from(this.targets.values()).filter(t => t.enabled).length,
      totalMetrics: this.metrics.size,
      totalAlerts: alerts.length,
      unacknowledgedAlerts: alerts.filter(a => !a.acknowledged).length,
      criticalAlerts: alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length,
      threatLevel: this.threatLevel,
      voidEntries: this.void.size,
      threatReports: this.threatReports.length,
    };
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private seedDefaultTargets(): void {
    const defaults: Array<{ name: string; type: TargetType; endpoint: string }> = [
      { name: 'cpu_usage', type: 'system', endpoint: '/metrics/cpu' },
      { name: 'memory_usage', type: 'system', endpoint: '/metrics/memory' },
      { name: 'request_rate', type: 'application', endpoint: '/metrics/requests' },
      { name: 'error_rate', type: 'application', endpoint: '/metrics/errors' },
      { name: 'agent_count', type: 'ecosystem', endpoint: '/metrics/agents' },
      { name: 'task_queue_depth', type: 'ecosystem', endpoint: '/metrics/tasks' },
    ];
    for (const d of defaults) this.addTarget(d);
    logger.info({ count: defaults.length }, 'Default monitoring targets seeded');
  }
}