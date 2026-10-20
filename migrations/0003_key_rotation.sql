CREATE TABLE issuer_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id uuid NOT NULL REFERENCES issuers (id) ON DELETE CASCADE,
    signing_seed_hex text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text
);

CREATE UNIQUE INDEX issuer_keys_active_idx
    ON issuer_keys (issuer_id)
    WHERE status = 'active';

CREATE INDEX issuer_keys_issuer_created_idx
    ON issuer_keys (issuer_id, created_at DESC);

INSERT INTO issuer_keys (issuer_id, signing_seed_hex, status)
SELECT id, signing_seed_hex, 'active'
FROM issuers;

ALTER TABLE credentials
    ADD COLUMN key_id uuid REFERENCES issuer_keys (id);

CREATE INDEX credentials_key_idx ON credentials (key_id);
