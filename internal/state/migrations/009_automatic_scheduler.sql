ALTER TABLE operation_latest ADD COLUMN request_kind TEXT NOT NULL DEFAULT 'manual'
    CHECK (request_kind IN ('manual', 'scheduled'));

CREATE TABLE automatic_schedule (
    singleton_id INTEGER PRIMARY KEY
        CHECK (singleton_id = 1),
    enabled INTEGER NOT NULL
        CHECK (enabled IN (0, 1)),
    time_zone TEXT NOT NULL
        CHECK (length(time_zone) BETWEEN 1 AND 128),
    local_minute INTEGER NOT NULL
        CHECK (local_minute BETWEEN 0 AND 1439),
    next_evaluation_utc TEXT NOT NULL
        CHECK (length(next_evaluation_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    last_triggered_at_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(last_triggered_at_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    last_trigger_local_date TEXT NOT NULL DEFAULT ''
        CHECK (
            length(last_trigger_local_date) IN (0, 10)
            AND last_trigger_local_date NOT GLOB '*[^0-9-]*'
        ),
    trigger_state TEXT NOT NULL DEFAULT 'idle'
        CHECK (trigger_state IN ('idle', 'claiming')),
    claimed_occurrence_utc TEXT NOT NULL DEFAULT ''
        CHECK (length(claimed_occurrence_utc) IN (0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)),
    reason_code TEXT NOT NULL DEFAULT 'schedule_saved'
        CHECK (
            length(reason_code) BETWEEN 1 AND 64
            AND reason_code NOT GLOB '*[^a-z0-9_]*'
        ),
    updated_at_utc TEXT NOT NULL
        CHECK (length(updated_at_utc) BETWEEN 20 AND 30),
    CHECK (
        (enabled = 0 AND next_evaluation_utc = '' AND trigger_state = 'idle' AND claimed_occurrence_utc = '')
        OR
        (enabled = 1 AND next_evaluation_utc <> '' AND (
            (trigger_state = 'idle' AND claimed_occurrence_utc = '')
            OR (trigger_state = 'claiming' AND claimed_occurrence_utc <> '')
        ))
    )
);
