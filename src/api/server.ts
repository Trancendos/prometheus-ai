/**
 * Prometheus AI — REST API Server
 *
 * Exposes monitoring, alerting, threat scanning, and Void Guardian
 * endpoints for the Trancendos mesh.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { MonitorEngine, TargetType, AlertSeverity } from '../monitoring/monitor-engine';
import { logger } from '../utils/logger';

// ── Bootstrap ──────────────────────────────────────────────────────────────

const app = express();
export const monitor = new MonitorEngine();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// ── Helpers ────────────────────────────────────────────────────────────────

function ok(res: Response, data: unknown, status = 200): void {
  res.status(status).json({ success: true, data, timestamp: new Date().toISOString() });
}

function fail(res: Response, message: string, status = 400): void {
  res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
}

// ── Health ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  ok(res, {
    status: 'healthy',
    service: 'prometheus-ai',
    uptime: process.uptime(),
    lockdown: monitor.isLockdownActive(),
    threatLevel: monitor.getCurrentThreatLevel(),
  });
});

app.get('/metrics', (_req, res) => {
  ok(res, {
    ...monitor.getStats(),
    memory: process.memoryUsage(),
    uptime: process.uptime(),
  });
});

// ── Monitoring Targets ─────────────────────────────────────────────────────

// GET /targets — list all monitoring targets
app.get('/targets', (req, res) => {
  const { type } = req.query;
  const targets = monitor.getTargets(type as TargetType | undefined);
  ok(res, { targets, count: targets.length });
});

// GET /targets/:id — get a specific target
app.get('/targets/:id', (req, res) => {
  const target = monitor.getTarget(req.params.id);
  if (!target) return fail(res, 'Target not found', 404);
  ok(res, target);
});

// POST /targets — add a monitoring target
app.post('/targets', (req, res) => {
  const { name, type, endpoint } = req.body;
  if (!name || !type || !endpoint) {
    return fail(res, 'name, type, endpoint are required');
  }
  const validTypes: TargetType[] = ['agent', 'service', 'database', 'api', 'system'];
  if (!validTypes.includes(type)) {
    return fail(res, `type must be one of: ${validTypes.join(', ')}`);
  }
  const target = monitor.addTarget({ name, type: type as TargetType, endpoint });
  ok(res, target, 201);
});

// PATCH /targets/:id/toggle — enable/disable a target
app.patch('/targets/:id/toggle', (req, res) => {
  const target = monitor.toggleTarget(req.params.id);
  if (!target) return fail(res, 'Target not found', 404);
  ok(res, target);
});

// DELETE /targets/:id — remove a target
app.delete('/targets/:id', (req, res) => {
  const deleted = monitor.deleteTarget(req.params.id);
  if (!deleted) return fail(res, 'Target not found', 404);
  ok(res, { deleted: true, id: req.params.id });
});

// ── Metrics ────────────────────────────────────────────────────────────────

// GET /metrics-data — list all metric series
app.get('/metrics-data', (req, res) => {
  const { targetId } = req.query;
  const metrics = monitor.getMetrics(targetId as string | undefined);
  ok(res, { metrics, count: metrics.length });
});

// GET /metrics-data/:targetId/:name — get a specific metric series
app.get('/metrics-data/:targetId/:name', (req, res) => {
  const series = monitor.getMetric(req.params.targetId, req.params.name);
  if (!series) return fail(res, 'Metric series not found', 404);
  ok(res, series);
});

// POST /metrics-data — record a metric value
app.post('/metrics-data', (req, res) => {
  const { targetId, name, value } = req.body;
  if (!targetId || !name || value === undefined) {
    return fail(res, 'targetId, name, value are required');
  }
  const series = monitor.recordMetric(targetId, name, Number(value));
  ok(res, series, 201);
});

// ── Alerts ─────────────────────────────────────────────────────────────────

// GET /alerts — list alerts
app.get('/alerts', (req, res) => {
  const includeAcknowledged = req.query.includeAcknowledged === 'true';
  const alerts = monitor.getAlerts(includeAcknowledged);
  ok(res, { alerts, count: alerts.length });
});

// POST /alerts — raise an alert
app.post('/alerts', (req, res) => {
  const { type, severity, source, message } = req.body;
  if (!type || !severity || !source || !message) {
    return fail(res, 'type, severity, source, message are required');
  }
  const validSeverities: AlertSeverity[] = ['info', 'warning', 'critical', 'emergency'];
  if (!validSeverities.includes(severity)) {
    return fail(res, `severity must be one of: ${validSeverities.join(', ')}`);
  }
  const alert = monitor.raiseAlert({ type, severity: severity as AlertSeverity, source, message });
  ok(res, alert, 201);
});

// PATCH /alerts/:id/acknowledge — acknowledge an alert
app.patch('/alerts/:id/acknowledge', (req, res) => {
  const { acknowledgedBy } = req.body;
  if (!acknowledgedBy) return fail(res, 'acknowledgedBy is required');
  const alert = monitor.acknowledgeAlert(req.params.id, acknowledgedBy);
  if (!alert) return fail(res, 'Alert not found', 404);
  ok(res, alert);
});

// ── Threat Management ──────────────────────────────────────────────────────

// GET /threat-level — current threat level
app.get('/threat-level', (_req, res) => {
  ok(res, { threatLevel: monitor.getCurrentThreatLevel() });
});

// POST /threat-scan — run a threat scan
app.post('/threat-scan', (req, res) => {
  const { initiatedBy } = req.body;
  if (!initiatedBy) return fail(res, 'initiatedBy is required');
  const report = monitor.scanForThreats(initiatedBy);
  ok(res, report, 201);
});

// GET /threat-reports — list recent threat reports
app.get('/threat-reports', (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 10;
  const reports = monitor.getThreatReports(limit);
  ok(res, { reports, count: reports.length });
});

// ── Emergency Lockdown ─────────────────────────────────────────────────────

// GET /lockdown — lockdown status
app.get('/lockdown', (_req, res) => {
  ok(res, { active: monitor.isLockdownActive() });
});

// POST /lockdown — initiate emergency lockdown
app.post('/lockdown', (req, res) => {
  const { reason, initiatedBy } = req.body;
  if (!reason || !initiatedBy) return fail(res, 'reason, initiatedBy are required');
  const result = monitor.initiateEmergencyLockdown(reason, initiatedBy);
  ok(res, result, result.success ? 200 : 409);
});

// DELETE /lockdown — lift lockdown
app.delete('/lockdown', (req, res) => {
  const { authorizedBy } = req.body;
  if (!authorizedBy) return fail(res, 'authorizedBy is required');
  const result = monitor.liftLockdown(authorizedBy);
  ok(res, result, result.success ? 200 : 409);
});

// ── Void Guardian ──────────────────────────────────────────────────────────

// GET /void — list void keys
app.get('/void', (_req, res) => {
  const keys = monitor.listVoidKeys();
  ok(res, { keys, count: keys.length });
});

// POST /void — store a value in the void
app.post('/void', (req, res) => {
  const { key, value, description, allowedAccessors } = req.body;
  if (!key || !value) return fail(res, 'key, value are required');
  const entry = monitor.storeInVoid(key, value, { description, allowedAccessors });
  ok(res, entry, 201);
});

// GET /void/:key — retrieve a value from the void
app.get('/void/:key', (req, res) => {
  const { requesterId } = req.query;
  if (!requesterId) return fail(res, 'requesterId query param is required');
  const value = monitor.retrieveFromVoid(req.params.key, requesterId as string);
  if (value === null) return fail(res, 'Key not found or access denied', 404);
  ok(res, { key: req.params.key, value });
});

// DELETE /void/:key — delete a void entry
app.delete('/void/:key', (req, res) => {
  const deleted = monitor.deleteFromVoid(req.params.key);
  if (!deleted) return fail(res, 'Key not found', 404);
  ok(res, { deleted: true, key: req.params.key });
});

// ── Stats ──────────────────────────────────────────────────────────────────

app.get('/stats', (_req, res) => {
  ok(res, monitor.getStats());
});

// ── Error Handler ──────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, 'Unhandled error');
  fail(res, err.message || 'Internal server error', 500);
});

export { app };