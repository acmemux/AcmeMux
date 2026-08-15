CREATE TABLE service_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    created_at TEXT NOT NULL
);

INSERT INTO service_metadata (id, created_at)
VALUES (1, CURRENT_TIMESTAMP);
