ALTER TABLE issuers
    ADD COLUMN signing_seed_hex text NOT NULL DEFAULT
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
ALTER TABLE issuers
    ALTER COLUMN signing_seed_hex DROP DEFAULT;

ALTER TABLE credentials
    ADD COLUMN idempotency_key text;

CREATE UNIQUE INDEX credentials_idempotency_idx
    ON credentials (issuer_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX credentials_issuer_idx ON credentials (issuer_id, issued_at DESC);

ALTER TABLE transparency_log
    ADD COLUMN event_type text NOT NULL DEFAULT 'issued'
        CHECK (event_type IN ('issued', 'revoked'));
ALTER TABLE transparency_log
    ADD COLUMN credential_id uuid REFERENCES credentials (id);

CREATE INDEX transparency_log_credential_idx
    ON transparency_log (credential_id, event_type);
