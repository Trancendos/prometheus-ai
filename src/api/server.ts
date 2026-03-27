/**
 * Prometheus AI — REST API Server
 *
 * Exposes monitoring, alerting, threat scanning, Void Guardian,
 * AND ecosystem-wide metrics collection endpoints for the Trancendos mesh.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { MonitorEngine, TargetType, AlertSeverity } from '../monitoring/monitor-engine';
import { EcosystemCollector } from '../monitoring/ecosystem-collector';
import { logger } from '../utils/logger';


// ============================================================================
// IAM MIDDLEWARE — Trancendos 2060 Standard (TRN-PROD-001)
// ============================================================================
import { createHash, createHmac } from 'crypto';

const IAM_JWT_SECRET = process.env.IAM_JWT_SECRET || process.env.JWT_SECRET || '';
const IAM_ALGORITHM = process.env.JWT_ALGORITHM || 'HS512';
const SERVICE_ID = 'prometheus';
const MESH_ADDRESS = process.env.MESH_ADDRESS || 'prometheus.agent.local';

function sha512Audit(data: string): string {
  return createHash('sha512').update(data).digest('hex');
}

function b64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64').toString('utf8');
}

interface JWTClaims {
  sub: string; email?: string; role?: string;
  active_role_level?: number; permissions?: string[];
  exp?: number; jti?: string;
}

function verifyIAMToken(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const header = JSON.parse(b64urlDecode(h));
    const alg = header.alg === 'HS512' ? 'sha512' : 'sha256';
    const expected = createHmac(alg, IAM_JWT_SECRET)
      .update(`${h}.${p}`).digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (expected !== sig) return null;
    const claims = JSON.parse(b64urlDecode(p)) as JWTClaims;
    if (claims.exp && Date.now() / 1000 > claims.exp) return null;
    return claims;
  } catch { return null; }
}

function requireIAMLevel(maxLevel: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) { res.status(401).json({ error: 'Authentication required', service: SERVICE_ID }); return; }
    const claims = verifyIAMToken(token);
    if (!claims) { res.status(401).json({ error: 'Invalid or expired token', service: SERVICE_ID }); return; }
    const level = claims.active_role_level ?? 6;
    if (level > maxLevel) {
      console.log(JSON.stringify({ level: 'audit', decision: 'DENY', service: SERVICE_ID,
        principal: claims.sub, requiredLevel: maxLevel, actualLevel: level, path: req.path,
        integrityHash: sha512Audit(`DENY:${claims.sub}:${req.path}:${Date.now()}`),
        timestamp: new Date().toISOString() }));
      res.status(403).json({ error: 'Insufficient privilege level', required: maxLevel, actual: level });
      return;
    }
    (req as any).principal = claims;
    next();
  };
}

function iamRequestMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Service-Id', SERVICE_ID);
  res.setHeader('X-Mesh-Address', MESH_ADDRESS);
  res.setHeader('X-IAM-Version', '1.0');
  const traceId = req.headers['x-trace-id'] || `prom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  res.setHeader('X-Trace-Id', traceId as string);
  (req as any).traceId = traceId;
  next();
}

function iamHealthStatus() {
  return {
    iam: {
      version: '1.0', algorithm: IAM_ALGORITHM,
      status: IAM_JWT_SECRET ? 'configured' : 'unconfigured',
      meshAddress: MESH_ADDRESS,
      routingProtocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
      cryptoMigrationPath: 'hmac_sha512 → ml_kem (2030) → hybrid_pqc (2040) → slh_dsa (2060)',
    },
  };
}
// ============================================================================
// END IAM MIDDLEWARE
// ============================================================================

// ── Bootstrap ────────────────────────────────────────────────────────────────

const app = express();
export const monitor = new MonitorEngine();
export const collector = new EcosystemCollector();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(iamRequestMiddleware);
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

function ok(res: Response, data: unknown, status = 200): void {
  res.status(status).json({ success: true, data, timestamp: new Date().toISOString() });
}

function fail(res: Response, message: string, status = 400): void {
  res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: HEALTH & CORE METRICS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/health', (_req, res) => {
  const ecosystemHealth = collector.getEcosystemHealth();
  ok(res, {
    status: 'healthy',
    service: 'prometheus-ai',
    role: 'ecosystem-monitor',
    uptime: process.uptime(),
    lockdown: monitor.isLockdownActive(),
    threatLevel: monitor.getCurrentThreatLevel(),
    ecosystem: {
      totalServices: ecosystemHealth.totalServices,
      onlineServices: ecosystemHealth.onlineServices,
      degradedServices: ecosystemHealth.degradedServices,
      offlineServices: ecosystemHealth.offlineServices,
      healthPercent: ecosystemHealth.overallHealthPercent,
    },
    ...iamHealthStatus(),
    mesh: {
      address: MESH_ADDRESS,
      protocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
    },
  });
});

// Internal metrics (prometheus-ai own stats)
app.get('/metrics', (_req, res) => {
  ok(res, {
    ...monitor.getStats(),
    collector: collector.getCollectorStats(),
    memory: process.memoryUsage(),
    uptime: process.uptime(),
  });
});

// Prometheus text format — ecosystem-wide (for external scrapers / Grafana)
app.get('/metrics/prometheus', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(collector.exportPrometheusText());
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: ECOSYSTEM METRICS INGESTION (services push here)
// ═══════════════════════════════════════════════════════════════════════════════

// POST /ecosystem/register — service self-registration
app.post('/ecosystem/register', (req, res) => {
  const { serviceId, name, tier, port, version, metadata } = req.body;
  if (!serviceId || !name || !port) {
    return fail(res, 'serviceId, name, port are required');
  }
  const reg = collector.registerService({ serviceId, name, tier, port, version, metadata });
  ok(res, reg, 201);
});

// POST /ecosystem/ingest — batch metrics push
app.post('/ecosystem/ingest', (req, res) => {
  const { serviceId, metrics: metricsBatch } = req.body;
  if (!serviceId || !Array.isArray(metricsBatch)) {
    return fail(res, 'serviceId and metrics[] are required');
  }
  const result = collector.ingestMetrics(serviceId, metricsBatch);
  ok(res, result, 201);
});

// POST /ecosystem/snapshot — service health snapshot push
app.post('/ecosystem/snapshot', (req, res) => {
  const { serviceId, ...data } = req.body;
  if (!serviceId) {
    return fail(res, 'serviceId is required');
  }
  const snapshot = collector.ingestSnapshot(serviceId, data);
  ok(res, snapshot, 201);
});

// GET /ecosystem/health — aggregated ecosystem health
app.get('/ecosystem/health', (_req, res) => {
  const health = collector.getEcosystemHealth();
  // Overlay threat level from MonitorEngine
  health.threatLevel = monitor.getCurrentThreatLevel();
  ok(res, health);
});

// GET /ecosystem/registry — list all registered services
app.get('/ecosystem/registry', (_req, res) => {
  const registry = collector.getRegistry();
  ok(res, { services: registry, count: registry.length });
});

// GET /ecosystem/registry/:serviceId — get specific service registration
app.get('/ecosystem/registry/:serviceId', (req, res) => {
  const reg = collector.getServiceRegistration(req.params.serviceId);
  if (!reg) return fail(res, 'Service not found in registry', 404);
  ok(res, reg);
});

// GET /ecosystem/dashboard — full dashboard payload
app.get('/ecosystem/dashboard', (_req, res) => {
  const health = collector.getEcosystemHealth();
  health.threatLevel = monitor.getCurrentThreatLevel();
  const stats = monitor.getStats();
  const collectorStats = collector.getCollectorStats();
  const alerts = monitor.getAlerts(false);

  ok(res, {
    ecosystem: health,
    monitoring: stats,
    collector: collectorStats,
    recentAlerts: alerts.slice(0, 20),
    lockdown: monitor.isLockdownActive(),
    timestamp: new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: MONITORING TARGETS (original prometheus-ai functionality)
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: METRICS DATA (original prometheus-ai functionality)
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: ALERTS
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: THREAT MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: EMERGENCY LOCKDOWN
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8: VOID GUARDIAN
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9: STATS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/stats', (_req, res) => {
  ok(res, {
    monitor: monitor.getStats(),
    collector: collector.getCollectorStats(),
  });
});

// ── Error Handler ────────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, 'Unhandled error');
  fail(res, err.message || 'Internal server error', 500);
});

export { app };