# ADR-0003: Key rotation and transparency-log consistency

- Status: Accepted
- Date: 2026-10-20

## Context

Issuers need to change signing keys without invalidating credentials that were
already issued. Offline verifiers also need a way to choose the right key when a
credential names one. Separately, the append-only transparency log must be able
to prove that a newer root extends an older root; otherwise a log could rewrite
history and still produce valid inclusion proofs.

## Decision

- Add `issuer_keys` with a generated `key_id`, seed, status
  (`active`, `retired`, `revoked`), and lifecycle timestamps. At most one key
  per issuer is active.
- New credentials sign `key_id` inside `CredentialClaims`. The field is
  optional and omitted when absent, preserving legacy signed bytes.
- Only the active key signs new credentials. Rotation retires the previous
  active key in the same transaction and creates a new active key. Retired keys
  remain valid for verifying credentials signed before rotation.
- Revoking an issuer key marks credentials signed by it invalid, even when their
  signatures are mathematically valid. Revoking the active key leaves the issuer
  unable to issue until it rotates again.
- Keep credentials with no `key_id` on the legacy issuer seed path. New
  credentials always store a key id.
- Expose the issuer keyring at `GET /api/issuers/{id}/keys`. `attest-cli` can
  consume that response via `--keyring`; `--public-key` remains available when
  key status is not needed.
- Add `GET /api/log/root` for current or historical roots and
  `GET /api/log/consistency` for RFC 6962 consistency proofs. Monitors can pin a
  root, fetch a later root and proof, and verify them with `attest-cli
  consistency`.

## Consequences

- Rotation is online and requires no re-signing or credential re-issuance.
- A compromised key can be invalidated without deleting the transparency log or
  rewriting credentials.
- Seeds remain development key material in PostgreSQL. KMS/HSM custody,
  automated monitors, and gossip are still required before production trust.
- Offline keyrings can be stale. A verifier that must detect key revocation
  needs a fresh keyring or an online check.
- The new RFC 6962 tree shape changes roots and inclusion proofs from the
  earlier duplicate-last-node implementation. Existing MVP data must be reset.

## Alternatives considered

- Re-sign every credential on rotation: rejected because the issuer may not
  control historical subject records and it breaks offline signatures.
- Keep one mutable issuer key and overwrite it: rejected because old
  credentials would stop verifying and compromise recovery would be impossible.
- Publish a new root without a consistency proof: rejected because a verifier
  cannot distinguish growth from a rewritten log.
- Duplicate the last node in odd layers: rejected because the resulting tree is
  not prefix-consistent, so no consistency proof can exist across some sizes.
