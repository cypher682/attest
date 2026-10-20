# ADR-0001: MVP scope and deferred infrastructure

- Status: Accepted
- Date: 2026-10-20

## Context

The full product specification describes a credential network with issuer
governance, key management, a transparency log, revocation, selective
disclosure, wallet recovery, integrations, and metering. The immediate goal is
a functional slice that proves issuance, holding, and verification.

## Decision

Build a Rust workspace with an HTTP API, a reusable verifier core, and a CLI.
Start with Ed25519 signing and verification as the smallest auditable primitive.
Use PostgreSQL for issuer, schema, credential, revocation, and log metadata.
Run locally with Docker Compose.

Defer KMS/HSM, key rotation ceremonies, consistency proofs and monitors,
selective disclosure, integrations, billing, and abuse detection.

## Consequences

- The MVP proves the core cryptographic flow and offline verification path.
- The transparency log is append-only but does not yet have the full
  consistency-proof and monitoring surface.
- Key storage is suitable for development only, not production issuers.
- The credential format remains behind `verifier-core` so it can be replaced
  without rewriting the API.

## Alternatives considered

- Start with the W3C data model and full proof suite: rejected for the first
  slice because the format decision needs its own ADR and test vectors.
- Build the full issuer governance workflow first: rejected because it does not
  prove the verification path.
