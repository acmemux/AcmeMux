CREATE TABLE operation_latest (
    singleton_id INTEGER PRIMARY KEY
        CHECK (singleton_id = 1),
    operation_id TEXT NOT NULL UNIQUE
        CHECK (
            length(operation_id) = 32
            AND operation_id NOT GLOB '*[^0-9a-f]*'
        ),
    reviewed_evidence_sha256 TEXT NOT NULL
        CHECK (
            length(reviewed_evidence_sha256) = 64
            AND reviewed_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    kind TEXT NOT NULL
        CHECK (kind = 'manual'),
    state TEXT NOT NULL
        CHECK (state IN (
            'queued', 'running', 'succeeded', 'failed', 'partial',
            'not_attempted', 'timed_out', 'interrupted', 'incompatible',
            'ambiguous'
        )),
    phase TEXT NOT NULL
        CHECK (phase IN ('', 'queued', 'revalidating', 'executing', 'refreshing_inventory')),
    requested_at_utc TEXT NOT NULL
        CHECK (length(requested_at_utc) BETWEEN 20 AND 30),
    started_at_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(started_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    finished_at_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(finished_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    updated_at_utc TEXT NOT NULL
        CHECK (length(updated_at_utc) BETWEEN 20 AND 30),
    reason_code TEXT NOT NULL DEFAULT ''
        CHECK (
            length(reason_code) <= 64
            AND reason_code NOT GLOB '*[^a-z0-9_]*'
        ),
    may_have_changed INTEGER NOT NULL DEFAULT 0
        CHECK (may_have_changed IN (0, 1)),
    inventory_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (inventory_state IN ('pending', 'refreshed', 'unavailable')),
    inventory_code TEXT NOT NULL DEFAULT ''
        CHECK (
            length(inventory_code) <= 64
            AND inventory_code NOT GLOB '*[^a-z0-9_]*'
        ),
    redacted_output TEXT NOT NULL DEFAULT ''
        CHECK (length(CAST(redacted_output AS BLOB)) <= 262144),
    output_truncated INTEGER NOT NULL DEFAULT 0
        CHECK (output_truncated IN (0, 1)),
    inventory_certificate_count INTEGER
        CHECK (
            inventory_certificate_count IS NULL
            OR inventory_certificate_count BETWEEN 0 AND 10000
        ),
    CHECK (
        (state = 'queued'
            AND phase = 'queued'
            AND started_at_utc = ''
            AND finished_at_utc = ''
            AND reason_code = ''
            AND may_have_changed = 0
            AND inventory_state = 'pending'
            AND inventory_code = ''
            AND redacted_output = ''
            AND output_truncated = 0
            AND inventory_certificate_count IS NULL)
        OR
        (state = 'running'
            AND phase IN ('revalidating', 'executing', 'refreshing_inventory')
            AND started_at_utc <> ''
            AND finished_at_utc = ''
            AND reason_code = ''
            AND inventory_state = 'pending'
            AND inventory_code = ''
            AND redacted_output = ''
            AND output_truncated = 0
            AND inventory_certificate_count IS NULL)
        OR
        (state NOT IN ('queued', 'running')
            AND phase = ''
            AND started_at_utc <> ''
            AND finished_at_utc <> ''
            AND reason_code <> ''
            AND (
                (inventory_state = 'pending'
                    AND inventory_code = ''
                    AND inventory_certificate_count IS NULL
                    AND state IN ('interrupted', 'ambiguous'))
                OR
                (inventory_state = 'refreshed'
                    AND inventory_code <> ''
                    AND inventory_certificate_count IS NOT NULL)
                OR
                (inventory_state = 'unavailable'
                    AND inventory_code <> ''
                    AND inventory_certificate_count IS NULL)
            ))
    )
);

CREATE TABLE operation_requested_item (
    operation_id TEXT NOT NULL
        REFERENCES operation_latest(operation_id) ON DELETE CASCADE,
    item_ordinal INTEGER NOT NULL
        CHECK (item_ordinal BETWEEN 0 AND 255),
    item_name TEXT NOT NULL
        CHECK (length(CAST(item_name AS BLOB)) BETWEEN 1 AND 255),
    PRIMARY KEY (operation_id, item_ordinal),
    UNIQUE (operation_id, item_name)
) WITHOUT ROWID;

CREATE TABLE operation_item_result (
    operation_id TEXT NOT NULL
        REFERENCES operation_latest(operation_id) ON DELETE CASCADE,
    item_ordinal INTEGER NOT NULL
        CHECK (item_ordinal BETWEEN 0 AND 255),
    item_name TEXT NOT NULL
        CHECK (length(CAST(item_name AS BLOB)) BETWEEN 1 AND 255),
    state TEXT NOT NULL
        CHECK (state IN ('completed', 'failed', 'not_attempted', 'ambiguous')),
    reason_code TEXT NOT NULL
        CHECK (
            length(reason_code) BETWEEN 1 AND 64
            AND reason_code NOT GLOB '*[^a-z0-9_]*'
        ),
    PRIMARY KEY (operation_id, item_ordinal),
    UNIQUE (operation_id, item_name)
) WITHOUT ROWID;
