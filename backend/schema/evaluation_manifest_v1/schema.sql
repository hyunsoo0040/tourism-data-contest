CREATE TABLE artifact_metadata (
    metadata_key TEXT NOT NULL PRIMARY KEY,
    metadata_value TEXT NOT NULL
);

CREATE TABLE manifest_seals (
    manifest_version TEXT NOT NULL PRIMARY KEY,
    catalog_sha256 TEXT NOT NULL CHECK (length(catalog_sha256) = 64),
    split_sha256 TEXT NOT NULL CHECK (length(split_sha256) = 64),
    membership_sha256 TEXT NOT NULL CHECK (length(membership_sha256) = 64),
    authority_request_sha256 TEXT NOT NULL CHECK (length(authority_request_sha256) = 64),
    logical_schema_sha256 TEXT NOT NULL CHECK (length(logical_schema_sha256) = 64),
    logical_seal_sha256 TEXT NOT NULL CHECK (length(logical_seal_sha256) = 64),
    canonicalization_version TEXT NOT NULL,
    dev_count INTEGER NOT NULL CHECK (dev_count = 24),
    blind_count INTEGER NOT NULL CHECK (blind_count = 12),
    total_count INTEGER NOT NULL CHECK (total_count = 36),
    sealed_at_utc TEXT NOT NULL
);

CREATE TABLE manifest_members (
    manifest_version TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal BETWEEN 1 AND 36),
    canonical_place_id TEXT NOT NULL CHECK (length(canonical_place_id) BETWEEN 1 AND 128),
    split TEXT NOT NULL CHECK (split IN ('DEV', 'BLIND')),
    PRIMARY KEY (manifest_version, member_ordinal),
    FOREIGN KEY (manifest_version) REFERENCES manifest_seals(manifest_version) ON DELETE RESTRICT,
    CHECK (
        (split = 'DEV' AND member_ordinal BETWEEN 1 AND 24)
        OR (split = 'BLIND' AND member_ordinal BETWEEN 25 AND 36)
    )
);

CREATE TABLE authority_consumptions (
    manifest_version TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL CHECK (length(binding_sha256) = 64),
    nonce_sha256 TEXT NOT NULL CHECK (length(nonce_sha256) = 64),
    action_sha256 TEXT NOT NULL CHECK (length(action_sha256) = 64),
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    state_sha256 TEXT NOT NULL CHECK (length(state_sha256) = 64),
    target_sha256 TEXT NOT NULL CHECK (length(target_sha256) = 64),
    token_sha256 TEXT NOT NULL CHECK (length(token_sha256) = 64),
    logical_seal_sha256 TEXT NOT NULL CHECK (length(logical_seal_sha256) = 64),
    reviewer TEXT NOT NULL,
    consumed_at_utc TEXT NOT NULL,
    PRIMARY KEY (binding_sha256, nonce_sha256),
    FOREIGN KEY (manifest_version) REFERENCES manifest_seals(manifest_version) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX ux_manifest_seals_logical_seal
ON manifest_seals(logical_seal_sha256);

CREATE UNIQUE INDEX ux_manifest_members_version_place
ON manifest_members(manifest_version, canonical_place_id);

CREATE INDEX idx_manifest_members_split
ON manifest_members(manifest_version, split, member_ordinal);

CREATE INDEX idx_authority_consumptions_request
ON authority_consumptions(request_sha256);

CREATE TRIGGER trg_artifact_metadata_update_immutable
BEFORE UPDATE ON artifact_metadata
BEGIN
    SELECT RAISE(ABORT, 'artifact_metadata rows are immutable');
END;

CREATE TRIGGER trg_artifact_metadata_delete_immutable
BEFORE DELETE ON artifact_metadata
BEGIN
    SELECT RAISE(ABORT, 'artifact_metadata rows are immutable');
END;

CREATE TRIGGER trg_manifest_seals_update_immutable
BEFORE UPDATE ON manifest_seals
BEGIN
    SELECT RAISE(ABORT, 'manifest_seals rows are immutable');
END;

CREATE TRIGGER trg_manifest_seals_delete_immutable
BEFORE DELETE ON manifest_seals
BEGIN
    SELECT RAISE(ABORT, 'manifest_seals rows are immutable');
END;

CREATE TRIGGER trg_manifest_members_update_immutable
BEFORE UPDATE ON manifest_members
BEGIN
    SELECT RAISE(ABORT, 'manifest_members rows are immutable');
END;

CREATE TRIGGER trg_manifest_members_delete_immutable
BEFORE DELETE ON manifest_members
BEGIN
    SELECT RAISE(ABORT, 'manifest_members rows are immutable');
END;

CREATE TRIGGER trg_authority_consumptions_update_immutable
BEFORE UPDATE ON authority_consumptions
BEGIN
    SELECT RAISE(ABORT, 'authority_consumptions rows are immutable');
END;

CREATE TRIGGER trg_authority_consumptions_delete_immutable
BEFORE DELETE ON authority_consumptions
BEGIN
    SELECT RAISE(ABORT, 'authority_consumptions rows are immutable');
END;
