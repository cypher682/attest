# Attest

MVP for the credential and verification network: institutions issue signed
credentials, holders get a share link and QR, and anyone can verify them online
or offline.

## MVP scope

- issuer onboarding with Ed25519 key ids and key rotation
- old-key verification and explicit issuer-key revocation
- credential schemas per issuer
- single and idempotent bulk issuance
- share link, QR, and status list
- online verification and offline CLI verification
- revocation with a downloadable status list
- SHA-256 Merkle transparency log with inclusion and consistency proofs

Deferred: KMS/HSM, automated log monitors, selective disclosure, employer bulk
portal, LMS connector, billing, abuse detection, public trust registry, and
wallet recovery.

## Run

```bash
docker compose up --build
```

API: http://localhost:8082

The database is available on port 5435. The schema and synthetic seed data are
applied on first start. The seed creates a trusted `Demo University` issuer with
an RFC 8032 test signing seed, an active key id, and one `DegreeCredential`
schema.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/issuers` | Create a pending issuer |
| GET | `/api/issuers/{id}` | Read an issuer |
| POST | `/api/issuers/{id}/trust` | Move a pending or suspended issuer to trusted |
| GET | `/api/issuers/{id}/public-key` | Active issuer Ed25519 public key |
| GET | `/api/issuers/{id}/keys` | Issuer keyring with key ids and statuses |
| POST | `/api/issuers/{id}/keys` | Rotate to a new active signing key |
| POST | `/api/issuers/{id}/keys/{key_id}/revoke` | Revoke a signing key |
| POST | `/api/issuers/{id}/schemas` | Create a credential schema |
| GET | `/api/issuers/{id}/schemas` | List an issuer's schemas |
| POST | `/api/credentials` | Issue one credential (supports `idempotency_key`) |
| POST | `/api/credentials/bulk` | Issue many credentials, with per-item errors |
| GET | `/api/credentials/{id}` | Read a credential and its signed form |
| GET | `/api/credentials/{id}/qr.svg` | QR code for the share link |
| GET | `/api/credentials/{id}/proof` | Merkle inclusion proof |
| POST | `/api/credentials/{id}/revoke` | Revoke a credential |
| GET | `/api/verify/{id}` | Verify signature, issuer trust, key, and status |
| GET | `/api/status-list` | Active and revoked credential ids |
| GET | `/api/log/root?tree_size=N` | Current or historical Merkle root |
| GET | `/api/log/consistency?first_size=N&second_size=M` | Log consistency proof |

## Smoke test

With the stack running:

```bash
bash scripts/smoke.sh
```

The script creates an issuer, trusts it, creates a schema, issues credentials,
checks the QR and proof endpoints, rotates the issuer key, verifies credentials
signed by both the retired and active keys, verifies a log consistency proof,
revokes a credential and a signing key, and exercises `attest-cli` offline
throughout.

## Offline verification

```bash
cargo run -p attest-cli -- verify \
  --credential credential.json \
  --keyring keyring.json \
  --proof proof.json \
  --status-list status-list.json
```

`credential.json` is the `signed_credential` object, `keyring.json` is the
`/api/issuers/{id}/keys` response, `proof.json` is the `/proof` response, and
`status-list.json` is the `/api/status-list` response. A single `--public-key`
still works when the key status is not needed. The command exits `0` when the
signature is valid, the key is not revoked, the proof verifies, and the
credential is not revoked; `1` when it is invalid or revoked; `2` on bad input.

Verify a log consistency proof:

```bash
cargo run -p attest-cli -- consistency \
  --proof consistency.json \
  --expected-first-root <pinned-root-hex>
```

`consistency.json` is the `/api/log/consistency` response. The command exits
`0` when the proof verifies and any pinned roots match, `1` when it does not,
and `2` on bad input.

## Test

```bash
make test
```

`verifier-core` covers signing, tamper rejection, optional key ids, the RFC 8032
seed vector, odd and even Merkle trees, and consistency proofs across tree
sizes.

## Reset local data

```bash
make down
```

## Layout

```text
crates/attest-api/       HTTP entry point
crates/verifier-core/    signing, verification, and Merkle proofs
crates/attest-cli/       offline verifier
migrations/              0001 scaffold, 0002 core tables, 0003 key rotation
db/seed.sql              synthetic demo issuer, key, and schema
scripts/smoke.sh         end-to-end issuance, verification, and revocation
docs/adr/                decisions
```

## Next slice

KMS/HSM key custody, automated log monitors and gossip, selective disclosure, a
holder wallet with recovery, and bulk revocation.
