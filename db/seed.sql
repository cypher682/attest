INSERT INTO issuers (id, name, status, signing_seed_hex)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Demo University',
    'trusted',
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
);

INSERT INTO issuer_keys (id, issuer_id, signing_seed_hex, status)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'active'
);

INSERT INTO credential_schemas (id, issuer_id, name, version, schema_json)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'DegreeCredential',
    1,
    '{"type":"object","required":["degree","year"]}'::jsonb
);
