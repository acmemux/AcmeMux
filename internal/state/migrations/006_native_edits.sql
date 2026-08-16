CREATE TABLE workspace_edit_journal (
    singleton_id INTEGER PRIMARY KEY
        CHECK (singleton_id = 1),
    transaction_id TEXT NOT NULL UNIQUE
        CHECK (
            length(transaction_id) = 32
            AND transaction_id NOT GLOB '*[^0-9a-f]*'
        ),
    phase TEXT NOT NULL
        CHECK (phase IN ('staging', 'prepared', 'replacing', 'finalizing')),
    working_directory TEXT NOT NULL
        CHECK (length(CAST(working_directory AS BLOB)) BETWEEN 1 AND 4095),
    configuration_path TEXT NOT NULL
        CHECK (length(CAST(configuration_path AS BLOB)) BETWEEN 1 AND 4095),
    created_at_utc TEXT NOT NULL
        CHECK (length(created_at_utc) BETWEEN 20 AND 30)
);

CREATE TABLE workspace_edit_journal_file (
    journal_id INTEGER NOT NULL
        REFERENCES workspace_edit_journal(singleton_id) ON DELETE CASCADE,
    file_ordinal INTEGER NOT NULL
        CHECK (file_ordinal BETWEEN 0 AND 256),
    role TEXT NOT NULL
        CHECK (role IN ('configuration', 'dotenv')),
    target_path TEXT NOT NULL
        CHECK (length(CAST(target_path AS BLOB)) BETWEEN 1 AND 4095),
    parent_path TEXT NOT NULL
        CHECK (length(CAST(parent_path AS BLOB)) BETWEEN 1 AND 4095),
    stage_basename TEXT NOT NULL
        CHECK (
            length(stage_basename) BETWEEN 1 AND 128
            AND instr(stage_basename, '/') = 0
        ),
    target_existed INTEGER NOT NULL
        CHECK (target_existed IN (0, 1)),
    parent_device_decimal TEXT NOT NULL
        CHECK (
            length(parent_device_decimal) BETWEEN 1 AND 20
            AND parent_device_decimal NOT GLOB '*[^0-9]*'
        ),
    parent_inode_decimal TEXT NOT NULL
        CHECK (
            length(parent_inode_decimal) BETWEEN 1 AND 20
            AND parent_inode_decimal NOT GLOB '*[^0-9]*'
        ),
    original_device_decimal TEXT NOT NULL
        CHECK (
            length(original_device_decimal) BETWEEN 1 AND 20
            AND original_device_decimal NOT GLOB '*[^0-9]*'
        ),
    original_inode_decimal TEXT NOT NULL
        CHECK (
            length(original_inode_decimal) BETWEEN 1 AND 20
            AND original_inode_decimal NOT GLOB '*[^0-9]*'
        ),
    original_mode INTEGER NOT NULL
        CHECK (original_mode BETWEEN 0 AND 4294967295),
    original_uid INTEGER NOT NULL
        CHECK (original_uid BETWEEN 0 AND 4294967295),
    original_gid INTEGER NOT NULL
        CHECK (original_gid BETWEEN 0 AND 4294967295),
    original_nlink_decimal TEXT NOT NULL
        CHECK (
            length(original_nlink_decimal) BETWEEN 1 AND 20
            AND original_nlink_decimal NOT GLOB '*[^0-9]*'
        ),
    original_size_bytes INTEGER NOT NULL
        CHECK (original_size_bytes >= 0),
    original_modified_at_utc TEXT NOT NULL
        CHECK (length(original_modified_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    original_changed_at_utc TEXT NOT NULL
        CHECK (length(original_changed_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    candidate_ready INTEGER NOT NULL DEFAULT 0
        CHECK (candidate_ready IN (0, 1)),
    candidate_device_decimal TEXT NOT NULL DEFAULT '0'
        CHECK (
            length(candidate_device_decimal) BETWEEN 1 AND 20
            AND candidate_device_decimal NOT GLOB '*[^0-9]*'
        ),
    candidate_inode_decimal TEXT NOT NULL DEFAULT '0'
        CHECK (
            length(candidate_inode_decimal) BETWEEN 1 AND 20
            AND candidate_inode_decimal NOT GLOB '*[^0-9]*'
        ),
    candidate_mode INTEGER NOT NULL DEFAULT 0
        CHECK (candidate_mode BETWEEN 0 AND 4294967295),
    candidate_uid INTEGER NOT NULL DEFAULT 0
        CHECK (candidate_uid BETWEEN 0 AND 4294967295),
    candidate_gid INTEGER NOT NULL DEFAULT 0
        CHECK (candidate_gid BETWEEN 0 AND 4294967295),
    candidate_nlink_decimal TEXT NOT NULL DEFAULT '0'
        CHECK (
            length(candidate_nlink_decimal) BETWEEN 1 AND 20
            AND candidate_nlink_decimal NOT GLOB '*[^0-9]*'
        ),
    candidate_size_bytes INTEGER NOT NULL DEFAULT 0
        CHECK (candidate_size_bytes >= 0),
    candidate_modified_at_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(candidate_modified_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    candidate_changed_at_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(candidate_changed_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    applied INTEGER NOT NULL DEFAULT 0
        CHECK (applied IN (0, 1)),
    PRIMARY KEY (journal_id, file_ordinal),
    UNIQUE (journal_id, target_path),
    UNIQUE (journal_id, parent_path, stage_basename)
) WITHOUT ROWID;
