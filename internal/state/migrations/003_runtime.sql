CREATE TABLE runtime_selection (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    canonical_path TEXT NOT NULL
        CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 4095),
    device_decimal TEXT NOT NULL
        CHECK (length(device_decimal) BETWEEN 1 AND 20),
    inode_decimal TEXT NOT NULL
        CHECK (length(inode_decimal) BETWEEN 1 AND 20),
    mode INTEGER NOT NULL
        CHECK (mode BETWEEN 0 AND 4294967295),
    uid INTEGER NOT NULL
        CHECK (uid BETWEEN 0 AND 4294967295),
    gid INTEGER NOT NULL
        CHECK (gid BETWEEN 0 AND 4294967295),
    size_bytes INTEGER NOT NULL
        CHECK (size_bytes BETWEEN 1 AND 536870912),
    modified_at_utc TEXT NOT NULL
        CHECK (length(modified_at_utc) BETWEEN 20 AND 30),
    changed_at_utc TEXT NOT NULL
        CHECK (length(changed_at_utc) BETWEEN 20 AND 30),
    sha256 TEXT NOT NULL
        CHECK (
            length(sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    version_kind TEXT NOT NULL
        CHECK (version_kind IN ('release', 'revision')),
    version_value TEXT NOT NULL
        CHECK (length(version_value) BETWEEN 1 AND 64),
    platform_os TEXT NOT NULL
        CHECK (length(platform_os) BETWEEN 1 AND 32),
    platform_arch TEXT NOT NULL
        CHECK (length(platform_arch) BETWEEN 1 AND 32),
    build_available INTEGER NOT NULL
        CHECK (build_available IN (0, 1)),
    build_go_version TEXT NOT NULL
        CHECK (length(build_go_version) <= 128),
    build_main_path TEXT NOT NULL
        CHECK (length(build_main_path) <= 256),
    build_main_version TEXT NOT NULL
        CHECK (length(build_main_version) <= 256),
    build_goos TEXT NOT NULL
        CHECK (length(build_goos) <= 32),
    build_goarch TEXT NOT NULL
        CHECK (length(build_goarch) <= 32),
    build_vcs_revision TEXT NOT NULL
        CHECK (length(build_vcs_revision) <= 40),
    build_vcs_modified_known INTEGER NOT NULL
        CHECK (build_vcs_modified_known IN (0, 1)),
    build_vcs_modified_valid INTEGER NOT NULL
        CHECK (build_vcs_modified_valid IN (0, 1)),
    build_vcs_modified INTEGER NOT NULL
        CHECK (build_vcs_modified IN (0, 1)),
    version_output TEXT NOT NULL
        CHECK (length(version_output) BETWEEN 1 AND 255),
    observed_at_utc TEXT NOT NULL
        CHECK (length(observed_at_utc) BETWEEN 20 AND 30),
    compatibility_manifest_id TEXT NOT NULL
        CHECK (length(compatibility_manifest_id) BETWEEN 1 AND 128),
    reviewed_at_utc TEXT NOT NULL
        CHECK (length(reviewed_at_utc) BETWEEN 20 AND 30)
);
