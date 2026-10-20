CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE issuers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'trusted', 'suspended', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credential_schemas (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id uuid NOT NULL REFERENCES issuers (id) ON DELETE CASCADE,
    name text NOT NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    schema_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer_id, name, version)
);

CREATE TABLE credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id uuid NOT NULL REFERENCES issuers (id),
    schema_id uuid NOT NULL REFERENCES credential_schemas (id),
    subject_ref text NOT NULL,
    claims jsonb NOT NULL,
    signature_hex text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'suspended')),
    issued_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credentials_subject_idx ON credentials (subject_ref);

CREATE TABLE revocation_entries (
    id bigserial PRIMARY KEY,
    credential_id uuid NOT NULL UNIQUE REFERENCES credentials (id) ON DELETE CASCADE,
    reason text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE transparency_log (
    id bigserial PRIMARY KEY,
    leaf_hash text NOT NULL UNIQUE,
    payload_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX transparency_log_created_idx ON transparency_log (created_at);
