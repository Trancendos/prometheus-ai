/**
 * Prometheus AI — Ecosystem-Wide Metrics Collector
 *
 * Centralized metrics ingestion for all 24 Trancendos mesh services.
 * Receives telemetry pushes from each service's resilience-layer,
 * aggregates ecosystem-wide health, and exposes Prometheus-compatible
 * text format for external scrapers.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 * Zero-cost compliant — no external dependencies
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// ── Types ─────────────────────────────────────────────────────────────

export type ServiceTier = 'core' | 'agent' | 'platform' | 'infrastructure' | 'marketplace';

export interface ServiceRegistration {
  serviceId: string;
  name: string;
  tier: ServiceTier;
  port: number;
  meshAddress: string;
  healthEndpoint: string;
  metricsEndpoint: string;
  version: string;
  registeredAt: Date;
  lastHeartbeat: Date;
  status: 'online' | 'degraded' | 'offline' | 'unknown';
  metadata: Record<string, unknown>;
}

export interface IngestedMetric {
  serviceId: string;
  name: string;
  type: 'counter' | 'gauge' | 'histogram';
  value: number;
  labels: Record<string, string>;
  timestamp: Date;
}

export interface ServiceSnapshot {
  serviceId: string;
  name: string;
  tier: ServiceTier;
  status: string;
  uptime: number;
  rps: number;
  errorRate: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
  activeConnections: number;
  memoryUsageMB: number;
  lastHeartbeat: Date;
  circuitBreakerState: string;
  eventBusQueueDepth: number;
}

export interface EcosystemHealth {
  timestamp: Date;
  totalServices: number;
  onlineServices: number;
  degradedServices: number;
  offlineServices: number;
  overallHealthPercent: number;
  ecosystemRPS: number;
  ecosystemErrorRate: number;
  avgLatencyMs: number;
  totalEventsProcessed: number;
  threatLevel: string;
  services: ServiceSnapshot[];
}

// ── Service Registry (all 24 services) ────────────────────────────────

const ECOSYSTEM_SERVICES: Array<{
  name: string; tier: ServiceTier; port: number;
}> = [
  // Wave 1 — Core
  { name: 'infinity-portal',   tier: 'core',           port: 3099 },
  // Wave 2 — Agents
  { name: 'cornelius-ai',      tier: 'agent',          port: 3000 },
  { name: 'the-dr-ai',         tier: 'agent',          port: 3001 },
  { name: 'norman-ai',         tier: 'agent',          port: 3002 },
  { name: 'guardian-ai',       tier: 'agent',          port: 3004 },
  { name: 'dorris-ai',         tier: 'agent',          port: 3005 },
  // Wave 3 — Platform
  { name: 'the-agora',         tier: 'platform',       port: 3010 },
  { name: 'the-citadel',       tier: 'platform',       port: 3011 },
  { name: 'the-hive',          tier: 'platform',       port: 3012 },
  { name: 'the-library',       tier: 'platform',       port: 3013 },
  { name: 'the-nexus',         tier: 'platform',       port: 3014 },
  { name: 'the-observatory',   tier: 'platform',       port: 3015 },
  { name: 'the-treasury',      tier: 'platform',       port: 3016 },
  { name: 'the-workshop',      tier: 'platform',       port: 3017 },
  { name: 'arcadia',           tier: 'platform',       port: 3018 },
  // Wave 4 — Agents (extended)
  { name: 'serenity-ai',       tier: 'agent',          port: 3020 },
  { name: 'oracle-ai',         tier: 'agent',          port: 3022 },
  { name: 'porter-family-ai',  tier: 'agent',          port: 3023 },
  { name: 'queen-ai',          tier: 'agent',          port: 3025 },
  { name: 'renik-ai',          tier: 'agent',          port: 3026 },
  { name: 'solarscene-ai',     tier: 'agent',          port: 3028 },
  // Wave 4 — Infrastructure
  { name: 'prometheus-ai',     tier: 'infrastructure', port: 3019 },
  { name: 'sentinel-ai',       tier: 'infrastructure', port: 3021 },
  // Wave 5 — Marketplace
  { name: 'api-marketplace',   tier: 'marketplace',    port: 3040 },
  { name: 'artifactory',       tier: 'marketplace',    port: 3041 },
  // Wave 6: The Studios
  { name: 'section7', port: 3050, wave: 6, category: 'studio', ista: 'Bert-Joen Kater' },
  { name: 'style-and-shoot', port: 3051, wave: 6, category: 'studio', ista: 'Madam Krystal' },
  { name: 'fabulousa', port: 3052, wave: 6, category: 'studio', ista: 'Baron Von Hilton' },
  { name: 'tranceflow', port: 3053, wave: 6, category: 'studio', ista: 'Junior Cesar' },
  { name: 'tateking', port: 3054, wave: 6, category: 'studio', ista: 'Benji & Sam' },
  { name: 'the-digitalgrid', port: 3055, wave: 6, category: 'studio', ista: 'Tyler Towncroft' },
];

// ── Ecosystem Collector ───────────────────────────────────────────────

export class EcosystemCollector {
  private registry: Map<string, ServiceRegistration> = new Map();
  private metrics: Map<string, IngestedMetric[]> = new Map();
  private snapshots: Map<string, ServiceSnapshot> = new Map();
  private readonly MAX_METRICS_PER_SERVICE = 5000;
  private readonly HEARTBEAT_TIMEOUT_MS = 120_000; // 2 minutes
  private heartbeatTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.seedRegistry();
    this.startHeartbeatMonitor();
    logger.info({ services: ECOSYSTEM_SERVICES.length }, 'EcosystemCollector initialized — all services registered');
  }

  // ── Service Registration ──────────────────────────────────────────

  private seedRegistry(): void {
    for (const svc of ECOSYSTEM_SERVICES) {
      const reg: ServiceRegistration = {
        serviceId: svc.name,
        name: svc.name,
        tier: svc.tier,
        port: svc.port,
        meshAddress: `${svc.name}.agent.local`,
        healthEndpoint: `http://${svc.name}:${svc.port}/health`,
        metricsEndpoint: `http://${svc.name}:${svc.port}/metrics`,
        version: '1.0.0',
        registeredAt: new Date(),
        lastHeartbeat: new Date(),
        status: 'unknown',
        metadata: {},
      };
      this.registry.set(svc.name, reg);
    }
  }

  registerService(params: {
    serviceId: string;
    name: string;
    tier?: ServiceTier;
    port: number;
    version?: string;
    metadata?: Record<string, unknown>;
  }): ServiceRegistration {
    const existing = this.registry.get(params.serviceId);
    const reg: ServiceRegistration = {
      serviceId: params.serviceId,
      name: params.name,
      tier: params.tier || existing?.tier || 'platform',
      port: params.port,
      meshAddress: `${params.name}.agent.local`,
      healthEndpoint: `http://${params.name}:${params.port}/health`,
      metricsEndpoint: `http://${params.name}:${params.port}/metrics`,
      version: params.version || '1.0.0',
      registeredAt: existing?.registeredAt || new Date(),
      lastHeartbeat: new Date(),
      status: 'online',
      metadata: params.metadata || {},
    };
    this.registry.set(params.serviceId, reg);
    logger.info({ serviceId: params.serviceId, port: params.port }, 'Service registered/updated');
    return reg;
  }

  getRegistry(): ServiceRegistration[] {
    return Array.from(this.registry.values());
  }

  getServiceRegistration(serviceId: string): ServiceRegistration | undefined {
    return this.registry.get(serviceId);
  }

  // ── Metrics Ingestion ─────────────────────────────────────────────

  ingestMetrics(serviceId: string, batch: Array<{
    name: string;
    type: 'counter' | 'gauge' | 'histogram';
    value: number;
    labels?: Record<string, string>;
  }>): { accepted: number; serviceId: string } {
    // Update heartbeat
    const reg = this.registry.get(serviceId);
    if (reg) {
      reg.lastHeartbeat = new Date();
      reg.status = 'online';
    }

    if (!this.metrics.has(serviceId)) {
      this.metrics.set(serviceId, []);
    }
    const store = this.metrics.get(serviceId)!;

    let accepted = 0;
    for (const m of batch) {
      store.push({
        serviceId,
        name: m.name,
        type: m.type,
        value: m.value,
        labels: m.labels || {},
        timestamp: new Date(),
      });
      accepted++;
    }

    // Trim to max
    while (store.length > this.MAX_METRICS_PER_SERVICE) {
      store.shift();
    }

    return { accepted, serviceId };
  }

  // ── Snapshot Ingestion (from service health endpoints) ────────────

  ingestSnapshot(serviceId: string, data: Partial<ServiceSnapshot>): ServiceSnapshot {
    const reg = this.registry.get(serviceId);
    if (reg) {
      reg.lastHeartbeat = new Date();
      reg.status = 'online';
    }

    const snapshot: ServiceSnapshot = {
      serviceId,
      name: data.name || serviceId,
      tier: data.tier || reg?.tier || 'platform',
      status: data.status || 'online',
      uptime: data.uptime ?? 0,
      rps: data.rps ?? 0,
      errorRate: data.errorRate ?? 0,
      p50Latency: data.p50Latency ?? 0,
      p95Latency: data.p95Latency ?? 0,
      p99Latency: data.p99Latency ?? 0,
      activeConnections: data.activeConnections ?? 0,
      memoryUsageMB: data.memoryUsageMB ?? 0,
      lastHeartbeat: new Date(),
      circuitBreakerState: data.circuitBreakerState || 'CLOSED',
      eventBusQueueDepth: data.eventBusQueueDepth ?? 0,
    };

    this.snapshots.set(serviceId, snapshot);
    return snapshot;
  }

  // ── Ecosystem Health Aggregation ──────────────────────────────────

  getEcosystemHealth(): EcosystemHealth {
    const services: ServiceSnapshot[] = [];
    let totalRPS = 0;
    let totalErrorRate = 0;
    let totalLatency = 0;
    let totalEvents = 0;
    let onlineCount = 0;
    let degradedCount = 0;
    let offlineCount = 0;
    let servicesWithData = 0;

    for (const [id, reg] of this.registry) {
      const snap = this.snapshots.get(id);
      const isTimedOut = Date.now() - reg.lastHeartbeat.getTime() > this.HEARTBEAT_TIMEOUT_MS;

      if (isTimedOut && reg.status === 'online') {
        reg.status = 'unknown';
      }

      const snapshot: ServiceSnapshot = snap || {
        serviceId: id,
        name: reg.name,
        tier: reg.tier,
        status: reg.status,
        uptime: 0,
        rps: 0,
        errorRate: 0,
        p50Latency: 0,
        p95Latency: 0,
        p99Latency: 0,
        activeConnections: 0,
        memoryUsageMB: 0,
        lastHeartbeat: reg.lastHeartbeat,
        circuitBreakerState: 'UNKNOWN',
        eventBusQueueDepth: 0,
      };

      // Override status if timed out
      if (isTimedOut) {
        snapshot.status = 'unknown';
      }

      services.push(snapshot);

      if (snapshot.status === 'online' || snapshot.status === 'healthy') {
        onlineCount++;
      } else if (snapshot.status === 'degraded') {
        degradedCount++;
      } else if (snapshot.status === 'offline' || snapshot.status === 'down') {
        offlineCount++;
      }

      if (snap) {
        totalRPS += snap.rps;
        totalErrorRate += snap.errorRate;
        totalLatency += snap.p50Latency;
        totalEvents += snap.eventBusQueueDepth;
        servicesWithData++;
      }
    }

    const totalServices = this.registry.size;
    const healthPercent = totalServices > 0
      ? ((onlineCount / totalServices) * 100)
      : 0;

    return {
      timestamp: new Date(),
      totalServices,
      onlineServices: onlineCount,
      degradedServices: degradedCount,
      offlineServices: offlineCount,
      overallHealthPercent: Math.round(healthPercent * 100) / 100,
      ecosystemRPS: Math.round(totalRPS * 100) / 100,
      ecosystemErrorRate: servicesWithData > 0
        ? Math.round((totalErrorRate / servicesWithData) * 10000) / 10000
        : 0,
      avgLatencyMs: servicesWithData > 0
        ? Math.round((totalLatency / servicesWithData) * 100) / 100
        : 0,
      totalEventsProcessed: totalEvents,
      threatLevel: 'green', // Will be overridden by MonitorEngine
      services: services.sort((a, b) => a.name.localeCompare(b.name)),
    };
  }

  // ── Prometheus Text Format Export ─────────────────────────────────

  exportPrometheusText(): string {
    const lines: string[] = [];
    const now = Date.now();

    // Ecosystem-level gauges
    const health = this.getEcosystemHealth();
    lines.push('# HELP trancendos_ecosystem_services_total Total registered services');
    lines.push('# TYPE trancendos_ecosystem_services_total gauge');
    lines.push(`trancendos_ecosystem_services_total ${health.totalServices}`);

    lines.push('# HELP trancendos_ecosystem_services_online Online services count');
    lines.push('# TYPE trancendos_ecosystem_services_online gauge');
    lines.push(`trancendos_ecosystem_services_online ${health.onlineServices}`);

    lines.push('# HELP trancendos_ecosystem_services_degraded Degraded services count');
    lines.push('# TYPE trancendos_ecosystem_services_degraded gauge');
    lines.push(`trancendos_ecosystem_services_degraded ${health.degradedServices}`);

    lines.push('# HELP trancendos_ecosystem_services_offline Offline services count');
    lines.push('# TYPE trancendos_ecosystem_services_offline gauge');
    lines.push(`trancendos_ecosystem_services_offline ${health.offlineServices}`);

    lines.push('# HELP trancendos_ecosystem_health_percent Overall health percentage');
    lines.push('# TYPE trancendos_ecosystem_health_percent gauge');
    lines.push(`trancendos_ecosystem_health_percent ${health.overallHealthPercent}`);

    lines.push('# HELP trancendos_ecosystem_rps Total requests per second');
    lines.push('# TYPE trancendos_ecosystem_rps gauge');
    lines.push(`trancendos_ecosystem_rps ${health.ecosystemRPS}`);

    lines.push('# HELP trancendos_ecosystem_error_rate Average error rate');
    lines.push('# TYPE trancendos_ecosystem_error_rate gauge');
    lines.push(`trancendos_ecosystem_error_rate ${health.ecosystemErrorRate}`);

    // Per-service metrics from snapshots
    lines.push('');
    lines.push('# HELP trancendos_service_status Service status (1=online, 0.5=degraded, 0=offline)');
    lines.push('# TYPE trancendos_service_status gauge');
    for (const snap of health.services) {
      const val = snap.status === 'online' || snap.status === 'healthy' ? 1
        : snap.status === 'degraded' ? 0.5 : 0;
      lines.push(`trancendos_service_status{service="${snap.serviceId}",tier="${snap.tier}"} ${val}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_rps Service requests per second');
    lines.push('# TYPE trancendos_service_rps gauge');
    for (const snap of health.services) {
      lines.push(`trancendos_service_rps{service="${snap.serviceId}"} ${snap.rps}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_error_rate Service error rate');
    lines.push('# TYPE trancendos_service_error_rate gauge');
    for (const snap of health.services) {
      lines.push(`trancendos_service_error_rate{service="${snap.serviceId}"} ${snap.errorRate}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_latency_p50_ms Service p50 latency in ms');
    lines.push('# TYPE trancendos_service_latency_p50_ms gauge');
    for (const snap of health.services) {
      lines.push(`trancendos_service_latency_p50_ms{service="${snap.serviceId}"} ${snap.p50Latency}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_latency_p95_ms Service p95 latency in ms');
    lines.push('# TYPE trancendos_service_latency_p95_ms gauge');
    for (const snap of health.services) {
      lines.push(`trancendos_service_latency_p95_ms{service="${snap.serviceId}"} ${snap.p95Latency}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_memory_mb Service memory usage in MB');
    lines.push('# TYPE trancendos_service_memory_mb gauge');
    for (const snap of health.services) {
      lines.push(`trancendos_service_memory_mb{service="${snap.serviceId}"} ${snap.memoryUsageMB}`);
    }

    lines.push('');
    lines.push('# HELP trancendos_service_circuit_breaker Circuit breaker state (0=closed, 1=open, 0.5=half_open)');
    lines.push('# TYPE trancendos_service_circuit_breaker gauge');
    for (const snap of health.services) {
      const val = snap.circuitBreakerState === 'OPEN' ? 1
        : snap.circuitBreakerState === 'HALF_OPEN' ? 0.5 : 0;
      lines.push(`trancendos_service_circuit_breaker{service="${snap.serviceId}"} ${val}`);
    }

    // Per-service ingested metrics
    lines.push('');
    lines.push('# HELP trancendos_ingested_metric Ingested metrics from services');
    lines.push('# TYPE trancendos_ingested_metric gauge');
    for (const [serviceId, metricList] of this.metrics) {
      // Get latest value for each unique metric name
      const latest = new Map<string, IngestedMetric>();
      for (const m of metricList) {
        latest.set(m.name, m);
      }
      for (const [name, m] of latest) {
        const labelStr = Object.entries(m.labels)
          .map(([k, v]) => `${k}="${v}"`)
          .join(',');
        const allLabels = labelStr
          ? `service="${serviceId}",${labelStr}`
          : `service="${serviceId}"`;
        lines.push(`trancendos_ingested_metric{${allLabels},metric="${name}"} ${m.value}`);
      }
    }

    return lines.join('\n') + '\n';
  }

  // ── Heartbeat Monitor ─────────────────────────────────────────────

  private startHeartbeatMonitor(): void {
    this.heartbeatTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, reg] of this.registry) {
        const age = now - reg.lastHeartbeat.getTime();
        if (age > this.HEARTBEAT_TIMEOUT_MS && reg.status === 'online') {
          reg.status = 'unknown';
          logger.warn({ serviceId: id, lastHeartbeat: reg.lastHeartbeat, ageMs: age },
            'Service heartbeat timeout — marking as unknown');
        }
        if (age > this.HEARTBEAT_TIMEOUT_MS * 3 && reg.status !== 'offline') {
          reg.status = 'offline';
          logger.error({ serviceId: id, ageMs: age },
            'Service heartbeat critically overdue — marking as offline');
        }
      }
    }, 30_000);
  }

  // ── Cleanup ───────────────────────────────────────────────────────

  shutdown(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    logger.info('EcosystemCollector shut down');
  }

  // ── Stats ─────────────────────────────────────────────────────────

  getCollectorStats(): {
    registeredServices: number;
    servicesWithMetrics: number;
    totalIngestedMetrics: number;
    servicesWithSnapshots: number;
  } {
    let totalMetrics = 0;
    for (const [, list] of this.metrics) {
      totalMetrics += list.length;
    }
    return {
      registeredServices: this.registry.size,
      servicesWithMetrics: this.metrics.size,
      totalIngestedMetrics: totalMetrics,
      servicesWithSnapshots: this.snapshots.size,
    };
  }
}