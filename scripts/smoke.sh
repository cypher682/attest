#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8082}"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [[ "$actual" != "$expected" ]]; then
    fail "$label: expected '$expected', got '$actual'"
  fi
  echo "ok: $label"
}

echo "health"
curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS "$BASE_URL/health/db" >/dev/null

echo "create issuer"
issuer_json="$(curl -fsS -X POST "$BASE_URL/api/issuers" \
  -H 'content-type: application/json' \
  -d '{"name":"Smoke University"}')"
issuer_id="$(jq -r '.id' <<<"$issuer_json")"
assert_eq "$(jq -r '.status' <<<"$issuer_json")" "pending" "issuer starts pending"
[[ "$issuer_id" != "null" && -n "$issuer_id" ]] || fail "issuer id missing"

echo "trust issuer"
trusted_json="$(curl -fsS -X POST "$BASE_URL/api/issuers/$issuer_id/trust")"
assert_eq "$(jq -r '.status' <<<"$trusted_json")" "trusted" "issuer trusted"

echo "public key"
public_key_json="$(curl -fsS "$BASE_URL/api/issuers/$issuer_id/public-key")"
public_key="$(jq -r '.public_key_hex' <<<"$public_key_json")"
initial_key_id="$(jq -r '.key_id' <<<"$public_key_json")"
[[ "$public_key" =~ ^[0-9a-f]{64}$ ]] || fail "public key is not 32-byte hex"
[[ "$initial_key_id" != "null" && -n "$initial_key_id" ]] || fail "key id missing"
echo "ok: public key shape"

echo "create schema"
schema_json="$(curl -fsS -X POST "$BASE_URL/api/issuers/$issuer_id/schemas" \
  -H 'content-type: application/json' \
  -d '{"name":"SmokeCredential","version":1,"schema_json":{"type":"object","required":["level"]}}')"
schema_id="$(jq -r '.id' <<<"$schema_json")"
[[ "$schema_id" != "null" && -n "$schema_id" ]] || fail "schema id missing"

issue_body="$(jq -nc \
  --arg issuer_id "$issuer_id" \
  --arg schema_id "$schema_id" \
  '{issuer_id:$issuer_id, schema_id:$schema_id, subject_ref:"smoke-subject-1", claims:{level:"gold"}, idempotency_key:"smoke-idem-1"}')"

echo "issue credential"
credential_json="$(curl -fsS -X POST "$BASE_URL/api/credentials" \
  -H 'content-type: application/json' \
  -d "$issue_body")"
credential_id="$(jq -r '.id' <<<"$credential_json")"
assert_eq "$(jq -r '.status' <<<"$credential_json")" "active" "credential active"
assert_eq "$(jq -r '.signed_credential.claims.credential_id' <<<"$credential_json")" "$credential_id" "signed claims bind credential id"
assert_eq "$(jq -r '.signed_credential.claims.key_id' <<<"$credential_json")" "$initial_key_id" "signed claims bind key id"

echo "issue is idempotent"
replay_json="$(curl -fsS -X POST "$BASE_URL/api/credentials" \
  -H 'content-type: application/json' \
  -d "$issue_body")"
assert_eq "$(jq -r '.id' <<<"$replay_json")" "$credential_id" "same idempotency key returns same credential"

echo "bulk issue"
bulk_body="$(jq -nc \
  --arg issuer_id "$issuer_id" \
  --arg schema_id "$schema_id" \
  '{items:[
      {issuer_id:$issuer_id, schema_id:$schema_id, subject_ref:"bulk-subject-1", claims:{level:"silver"}},
      {issuer_id:$issuer_id, schema_id:"00000000-0000-0000-0000-000000000099", subject_ref:"bulk-subject-2", claims:{level:"bronze"}}
    ]}')"
bulk_json="$(curl -fsS -X POST "$BASE_URL/api/credentials/bulk" \
  -H 'content-type: application/json' \
  -d "$bulk_body")"
assert_eq "$(jq '.issued | length' <<<"$bulk_json")" "1" "bulk issued one credential"
assert_eq "$(jq '.errors | length' <<<"$bulk_json")" "1" "bulk reports one error"

echo "qr"
content_type="$(curl -fsS -o /dev/null -w '%{content_type}' "$BASE_URL/api/credentials/$credential_id/qr.svg")"
[[ "$content_type" == image/svg+xml* ]] || fail "unexpected qr content type: $content_type"
echo "ok: qr content type"

echo "proof"
proof_json="$(curl -fsS "$BASE_URL/api/credentials/$credential_id/proof")"
assert_eq "$(jq -r '.credential_id' <<<"$proof_json")" "$credential_id" "proof credential id"
[[ "$(jq -r '.audit_path | length' <<<"$proof_json")" -ge 0 ]] || fail "audit path missing"
[[ "$(jq -r '.root_hash' <<<"$proof_json")" =~ ^[0-9a-f]{64}$ ]] || fail "root hash invalid"
echo "ok: proof shape"

echo "log root before rotation"
root_before_json="$(curl -fsS "$BASE_URL/api/log/root")"
first_size="$(jq -r '.tree_size' <<<"$root_before_json")"
first_root="$(jq -r '.root_hash' <<<"$root_before_json")"
[[ "$first_size" -ge 1 ]] || fail "log is empty"
[[ "$first_root" =~ ^[0-9a-f]{64}$ ]] || fail "log root invalid"

echo "list issuer keys"
keys_json="$(curl -fsS "$BASE_URL/api/issuers/$issuer_id/keys")"
assert_eq "$(jq -r --arg id "$initial_key_id" '.keys | map(select(.key_id == $id)) | length' <<<"$keys_json")" "1" "initial key listed"
assert_eq "$(jq -r --arg id "$initial_key_id" '.keys | map(select(.key_id == $id))[0].status' <<<"$keys_json")" "active" "initial key active"

echo "rotate issuer key"
rotate_json="$(curl -fsS -X POST "$BASE_URL/api/issuers/$issuer_id/keys")"
new_key_id="$(jq -r '.key.key_id' <<<"$rotate_json")"
assert_eq "$(jq -r '.previous_key_id' <<<"$rotate_json")" "$initial_key_id" "rotation reports previous key"
assert_eq "$(jq -r '.key.status' <<<"$rotate_json")" "active" "new key active"
[[ "$new_key_id" != "$initial_key_id" ]] || fail "rotation did not create a new key"

echo "public key rotates"
new_public_key="$(curl -fsS "$BASE_URL/api/issuers/$issuer_id/public-key" | jq -r '.public_key_hex')"
[[ "$new_public_key" != "$public_key" ]] || fail "public key did not change"
[[ "$new_public_key" =~ ^[0-9a-f]{64}$ ]] || fail "rotated public key is not 32-byte hex"

echo "issue credential with rotated key"
issue_body_2="$(jq -nc \
  --arg issuer_id "$issuer_id" \
  --arg schema_id "$schema_id" \
  '{issuer_id:$issuer_id, schema_id:$schema_id, subject_ref:"smoke-subject-2", claims:{level:"platinum"}, idempotency_key:"smoke-idem-2"}')"
credential_2_json="$(curl -fsS -X POST "$BASE_URL/api/credentials" \
  -H 'content-type: application/json' \
  -d "$issue_body_2")"
credential_2_id="$(jq -r '.id' <<<"$credential_2_json")"
assert_eq "$(jq -r '.signed_credential.claims.key_id' <<<"$credential_2_json")" "$new_key_id" "new credential uses rotated key"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
jq '.signed_credential' <<<"$credential_json" >"$workdir/credential.json"
jq '.signed_credential' <<<"$credential_2_json" >"$workdir/credential-2.json"
printf '%s' "$proof_json" >"$workdir/proof.json"

echo "fetch keyring"
keyring_json="$(curl -fsS "$BASE_URL/api/issuers/$issuer_id/keys")"
printf '%s' "$keyring_json" >"$workdir/keyring.json"
assert_eq "$(jq -r --arg id "$initial_key_id" '.keys | map(select(.key_id == $id))[0].status' <<<"$keyring_json")" "retired" "old key retired"
assert_eq "$(jq -r --arg id "$new_key_id" '.keys | map(select(.key_id == $id))[0].status' <<<"$keyring_json")" "active" "new key active in keyring"

echo "offline cli verify old credential with retired key"
cli_out="$(cargo run --quiet -p attest-cli -- verify \
  --credential "$workdir/credential.json" \
  --keyring "$workdir/keyring.json" \
  --proof "$workdir/proof.json")"
assert_eq "$(jq -r '.signature_valid' <<<"$cli_out")" "true" "cli old signature valid"
assert_eq "$(jq -r '.key_status' <<<"$cli_out")" "retired" "cli reports retired key"
assert_eq "$(jq -r '.inclusion_proved' <<<"$cli_out")" "true" "cli proof verifies"
assert_eq "$(jq -r '.status' <<<"$cli_out")" "valid" "cli old credential valid"

echo "offline cli verify new credential with active key"
cli_new_out="$(cargo run --quiet -p attest-cli -- verify \
  --credential "$workdir/credential-2.json" \
  --keyring "$workdir/keyring.json")"
assert_eq "$(jq -r '.signature_valid' <<<"$cli_new_out")" "true" "cli new signature valid"
assert_eq "$(jq -r '.key_status' <<<"$cli_new_out")" "active" "cli reports active key"
assert_eq "$(jq -r '.status' <<<"$cli_new_out")" "valid" "cli new credential valid"

echo "log consistency proof"
root_after_json="$(curl -fsS "$BASE_URL/api/log/root")"
second_size="$(jq -r '.tree_size' <<<"$root_after_json")"
[[ "$second_size" -gt "$first_size" ]] || fail "log did not grow after rotation"
consistency_json="$(curl -fsS "$BASE_URL/api/log/consistency?first_size=$first_size&second_size=$second_size")"
printf '%s' "$consistency_json" >"$workdir/consistency.json"
assert_eq "$(jq -r '.first_size' <<<"$consistency_json")" "$first_size" "consistency first size"
assert_eq "$(jq -r '.second_size' <<<"$consistency_json")" "$second_size" "consistency second size"
assert_eq "$(jq -r '.first_root' <<<"$consistency_json")" "$first_root" "consistency pins stored root"

echo "offline cli verify log consistency"
consistency_out="$(cargo run --quiet -p attest-cli -- consistency \
  --proof "$workdir/consistency.json" \
  --expected-first-root "$first_root")"
assert_eq "$(jq -r '.consistent' <<<"$consistency_out")" "true" "cli consistency proof verifies"

echo "verify active"
verify_json="$(curl -fsS "$BASE_URL/api/verify/$credential_id")"
assert_eq "$(jq -r '.valid' <<<"$verify_json")" "true" "active credential valid"
assert_eq "$(jq -r '.status' <<<"$verify_json")" "valid" "active credential status"
assert_eq "$(jq -r '.key_status' <<<"$verify_json")" "retired" "old credential uses retired key"
verify_2_json="$(curl -fsS "$BASE_URL/api/verify/$credential_2_id")"
assert_eq "$(jq -r '.valid' <<<"$verify_2_json")" "true" "new credential valid"
assert_eq "$(jq -r '.key_status' <<<"$verify_2_json")" "active" "new credential uses active key"

echo "revoke"
revoke_json="$(curl -fsS -X POST "$BASE_URL/api/credentials/$credential_id/revoke" \
  -H 'content-type: application/json' \
  -d '{"reason":"smoke test"}')"
assert_eq "$(jq -r '.status' <<<"$revoke_json")" "revoked" "revocation recorded"

echo "verify revoked"
verify_revoked="$(curl -fsS "$BASE_URL/api/verify/$credential_id")"
assert_eq "$(jq -r '.valid' <<<"$verify_revoked")" "false" "revoked credential invalid"
assert_eq "$(jq -r '.status' <<<"$verify_revoked")" "revoked" "revoked credential status"
assert_eq "$(jq -r '.revocation_reason' <<<"$verify_revoked")" "smoke test" "revocation reason surfaced"

echo "status list"
status_json="$(curl -fsS "$BASE_URL/api/status-list")"
[[ "$(jq -r --arg id "$credential_id" '.revoked | map(select(.credential_id == $id)) | length' <<<"$status_json")" == "1" ]] || fail "revoked credential missing from status list"
echo "ok: status list contains revoked credential"

printf '%s' "$status_json" >"$workdir/status-list.json"

echo "offline cli verify detects revocation"
set +e
cli_revoked="$(cargo run --quiet -p attest-cli -- verify \
  --credential "$workdir/credential.json" \
  --keyring "$workdir/keyring.json" \
  --status-list "$workdir/status-list.json" 2>/dev/null)"
cli_code=$?
set -e
assert_eq "$cli_code" "1" "cli exits non-zero for revoked credential"
assert_eq "$(jq -r '.status' <<<"$cli_revoked")" "revoked" "cli reports revoked"

echo "revoke active issuer key"
revoke_key_json="$(curl -fsS -X POST "$BASE_URL/api/issuers/$issuer_id/keys/$new_key_id/revoke" \
  -H 'content-type: application/json' \
  -d '{"reason":"smoke key compromise"}')"
assert_eq "$(jq -r '.status' <<<"$revoke_key_json")" "revoked" "issuer key revoked"

echo "verify credential signed by revoked key"
verify_key_revoked="$(curl -fsS "$BASE_URL/api/verify/$credential_2_id")"
assert_eq "$(jq -r '.valid' <<<"$verify_key_revoked")" "false" "credential with revoked key invalid"
assert_eq "$(jq -r '.status' <<<"$verify_key_revoked")" "issuer_key_revoked" "revoked key status surfaced"

keyring_revoked_json="$(curl -fsS "$BASE_URL/api/issuers/$issuer_id/keys")"
printf '%s' "$keyring_revoked_json" >"$workdir/keyring-revoked.json"
set +e
cli_key_revoked="$(cargo run --quiet -p attest-cli -- verify \
  --credential "$workdir/credential-2.json" \
  --keyring "$workdir/keyring-revoked.json" 2>/dev/null)"
cli_key_code=$?
set -e
assert_eq "$cli_key_code" "1" "cli exits non-zero for revoked key"
assert_eq "$(jq -r '.status' <<<"$cli_key_revoked")" "issuer_key_revoked" "cli reports revoked issuer key"

echo "PASS"
