CREATE TABLE administrator (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    password_verifier TEXT NOT NULL,
    auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    created_at_unix INTEGER NOT NULL,
    password_changed_at_unix INTEGER NOT NULL,
    CHECK (length(password_verifier) BETWEEN 1 AND 1024)
);

CREATE TABLE identity_sessions (
    id INTEGER PRIMARY KEY,
    administrator_id INTEGER NOT NULL CHECK (administrator_id = 1),
    auth_epoch INTEGER NOT NULL CHECK (auth_epoch > 0),
    current_token_hash BLOB NOT NULL UNIQUE
        CHECK (length(current_token_hash) = 32),
    previous_token_hash BLOB UNIQUE
        CHECK (previous_token_hash IS NULL OR length(previous_token_hash) = 32),
    previous_valid_until_unix INTEGER,
    csrf_token_hash BLOB NOT NULL CHECK (length(csrf_token_hash) = 32),
    created_at_unix INTEGER NOT NULL,
    last_seen_at_unix INTEGER NOT NULL,
    idle_expires_at_unix INTEGER NOT NULL,
    absolute_expires_at_unix INTEGER NOT NULL,
    rotate_after_unix INTEGER NOT NULL,
    FOREIGN KEY (administrator_id)
        REFERENCES administrator(singleton_id) ON DELETE CASCADE,
    CHECK (
        (previous_token_hash IS NULL) =
        (previous_valid_until_unix IS NULL)
    ),
    CHECK (created_at_unix <= last_seen_at_unix),
    CHECK (last_seen_at_unix <= idle_expires_at_unix),
    CHECK (idle_expires_at_unix <= absolute_expires_at_unix)
);

CREATE INDEX identity_sessions_expiry
    ON identity_sessions (idle_expires_at_unix, absolute_expires_at_unix);
