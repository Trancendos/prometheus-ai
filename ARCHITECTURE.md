# Prometheus AI - Repository Architecture

## Purpose

`prometheus-ai` is a modular monitoring and alerting service in the Trancendos ecosystem.

## Module Boundaries

- `src/index.ts`: service bootstrap and lifecycle (`start`, `stop`, `getStatus`)
- `dist/`: build artifacts only (not committed)
- `.github/workflows/`: security and dependency governance automation

## Integration Model

This repository is designed as an independent service repo.

- Internal logic should remain self-contained.
- Shared contracts should be consumed through **versioned packages** (not workspace-only references).
- Inter-service integration should happen through stable APIs/events and explicit versioning.

## Security and Dependency Controls

- CVE scanning and advisory audits run in CI.
- Dependency drift is checked against an N/N-1 policy.
- Dependabot updates dependencies continuously.

## Required Cross-Repo Contracts

To keep modular boundaries clear across the ecosystem:

1. Shared types/interfaces must live in `shared-core` (published/tagged version).
2. Service-to-service messages should have schema contracts (OpenAPI/JSON schema/protobuf).
3. Integration ownership should be mapped in CODEOWNERS and architecture docs in each repo.
