CREATE TABLE workspace_selection (
    singleton_id INTEGER PRIMARY KEY
        CHECK (singleton_id = 1),
    configuration_source TEXT NOT NULL
        CHECK (configuration_source IN ('explicit', 'conventional_yml', 'conventional_yaml')),
    adoptable INTEGER NOT NULL
        CHECK (adoptable = 1),
    reviewed_evidence_sha256 TEXT NOT NULL
        CHECK (
            length(reviewed_evidence_sha256) = 64
            AND reviewed_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    observed_at_utc TEXT NOT NULL
        CHECK (length(observed_at_utc) BETWEEN 20 AND 30),
    reviewed_at_utc TEXT NOT NULL
        CHECK (length(reviewed_at_utc) BETWEEN 20 AND 30)
);

CREATE TABLE workspace_path_observation (
    selection_id INTEGER NOT NULL
        REFERENCES workspace_selection(singleton_id) ON DELETE CASCADE,
    path_ordinal INTEGER NOT NULL
        CHECK (path_ordinal BETWEEN 0 AND 258),
    role TEXT NOT NULL
        CHECK (role IN ('working_directory', 'configuration', 'storage', 'dotenv', 'webroot')),
    reference_text TEXT NOT NULL
        CHECK (length(CAST(reference_text AS BLOB)) <= 4095),
    canonical_path TEXT NOT NULL
        CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 4095),
    exists_flag INTEGER NOT NULL
        CHECK (exists_flag = 1),
    path_type TEXT NOT NULL
        CHECK (path_type IN ('directory', 'regular')),
    device_decimal TEXT NOT NULL
        CHECK (
            length(device_decimal) BETWEEN 1 AND 20
            AND device_decimal NOT GLOB '*[^0-9]*'
        ),
    inode_decimal TEXT NOT NULL
        CHECK (
            length(inode_decimal) BETWEEN 1 AND 20
            AND inode_decimal NOT GLOB '*[^0-9]*'
        ),
    mode INTEGER NOT NULL
        CHECK (mode BETWEEN 0 AND 4294967295),
    uid INTEGER NOT NULL
        CHECK (uid BETWEEN 0 AND 4294967295),
    gid INTEGER NOT NULL
        CHECK (gid BETWEEN 0 AND 4294967295),
    nlink_decimal TEXT NOT NULL
        CHECK (
            length(nlink_decimal) BETWEEN 1 AND 20
            AND nlink_decimal NOT GLOB '*[^0-9]*'
        ),
    size_bytes INTEGER NOT NULL
        CHECK (size_bytes >= 0),
    modified_at_utc TEXT NOT NULL
        CHECK (length(modified_at_utc) BETWEEN 20 AND 30),
    changed_at_utc TEXT NOT NULL
        CHECK (length(changed_at_utc) BETWEEN 20 AND 30),
    readable INTEGER NOT NULL
        CHECK (readable IN (0, 1)),
    writable INTEGER NOT NULL
        CHECK (writable IN (0, 1)),
    searchable INTEGER NOT NULL
        CHECK (searchable IN (0, 1)),
    safe_flag INTEGER NOT NULL
        CHECK (safe_flag = 1),
    PRIMARY KEY (selection_id, path_ordinal)
) WITHOUT ROWID;

CREATE TABLE workspace_component_observation (
    selection_id INTEGER NOT NULL,
    path_ordinal INTEGER NOT NULL,
    component_ordinal INTEGER NOT NULL
        CHECK (component_ordinal BETWEEN 0 AND 63),
    canonical_path TEXT NOT NULL
        CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 4095),
    path_type TEXT NOT NULL
        CHECK (path_type IN ('directory', 'regular')),
    device_decimal TEXT NOT NULL
        CHECK (
            length(device_decimal) BETWEEN 1 AND 20
            AND device_decimal NOT GLOB '*[^0-9]*'
        ),
    inode_decimal TEXT NOT NULL
        CHECK (
            length(inode_decimal) BETWEEN 1 AND 20
            AND inode_decimal NOT GLOB '*[^0-9]*'
        ),
    mode INTEGER NOT NULL
        CHECK (mode BETWEEN 0 AND 4294967295),
    uid INTEGER NOT NULL
        CHECK (uid BETWEEN 0 AND 4294967295),
    gid INTEGER NOT NULL
        CHECK (gid BETWEEN 0 AND 4294967295),
    readable INTEGER NOT NULL
        CHECK (readable IN (0, 1)),
    writable INTEGER NOT NULL
        CHECK (writable IN (0, 1)),
    searchable INTEGER NOT NULL
        CHECK (searchable IN (0, 1)),
    PRIMARY KEY (selection_id, path_ordinal, component_ordinal),
    FOREIGN KEY (selection_id, path_ordinal)
        REFERENCES workspace_path_observation(selection_id, path_ordinal)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE workspace_review_diagnostic (
    selection_id INTEGER NOT NULL
        REFERENCES workspace_selection(singleton_id) ON DELETE CASCADE,
    diagnostic_ordinal INTEGER NOT NULL
        CHECK (diagnostic_ordinal BETWEEN 0 AND 1023),
    code TEXT NOT NULL
        CHECK (length(CAST(code AS BLOB)) BETWEEN 1 AND 64),
    severity TEXT NOT NULL
        CHECK (severity = 'notice'),
    role TEXT NOT NULL
        CHECK (role IN ('working_directory', 'configuration', 'storage', 'dotenv', 'webroot')),
    path_text TEXT NOT NULL
        CHECK (length(CAST(path_text AS BLOB)) BETWEEN 1 AND 4095),
    component_text TEXT NOT NULL
        CHECK (length(CAST(component_text AS BLOB)) <= 4095),
    detail TEXT NOT NULL
        CHECK (length(CAST(detail AS BLOB)) BETWEEN 1 AND 256),
    PRIMARY KEY (selection_id, diagnostic_ordinal)
) WITHOUT ROWID;
