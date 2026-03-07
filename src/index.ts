/**
 * Prometheus AI — Entry Point
 *
 * Monitoring, alerting, Void Guardian, and ecosystem-wide metrics
 * collection service for the Trancendos mesh.
 * Tracks all 24+ agents and services, detects anomalies, manages threat levels,
 * and aggregates ecosystem health telemetry.
 * Zero-cost compliant — no LLM calls.
 *
 * Port: 3019
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { app, monitor, collector } from './api/server';
import { logger } from './utils/logger';

const PORT = Number(process.env.PORT ?? 3019);
const HOST = process.env.HOST ?? '0.0.0.0';

// ── Startup ──────────────────────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  logger.info('Prometheus AI starting up...');

  const server = app.listen(PORT, HOST, () => {
    logger.info(
      { port: PORT, host: HOST, env: process.env.NODE_ENV ?? 'development' },
      '🔥 Prometheus AI is online — The Void is watching | Ecosystem Collector active',
    );
  });

  // ── Periodic Threat Assessment (every 5 minutes) ─────────────────────────
  const THREAT_INTERVAL = Number(process.env.THREAT_INTERVAL_MS ?? 5 * 60 * 1000);
  const threatTimer = setInterval(() => {
    try {
      const threatLevel = monitor.getCurrentThreatLevel();
      const stats = monitor.getStats();
      const collectorStats = collector.getCollectorStats();
      logger.info(
        {
          threatLevel,
          totalTargets: stats.totalTargets,
          enabledTargets: stats.enabledTargets,
          totalAlerts: stats.totalAlerts,
          unacknowledgedAlerts: stats.unacknowledgedAlerts,
          lockdownActive: monitor.isLockdownActive(),
          ecosystemServices: collectorStats.registeredServices,
          servicesReporting: collectorStats.servicesWithSnapshots,
          totalIngestedMetrics: collectorStats.totalIngestedMetrics,
        },
        '🔥 Prometheus periodic threat assessment + ecosystem status',
      );

      if (threatLevel === 'red' && !monitor.isLockdownActive()) {
        logger.warn('⚠️  Threat level RED — consider initiating emergency lockdown');
      }
    } catch (err) {
      logger.error({ err }, 'Periodic threat assessment failed');
    }
  }, THREAT_INTERVAL);

  // ── Graceful Shutdown ────────────────────────────────────────────────────
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    clearInterval(threatTimer);
    collector.shutdown();
    server.close(() => {
      logger.info('Prometheus AI shut down cleanly');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 30_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error({ err }, 'Uncaught exception');
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled rejection');
    process.exit(1);
  });
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Bootstrap failed');
  process.exit(1);
});