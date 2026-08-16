ALTER TABLE workspace_edit_journal
    ADD COLUMN bootstrap INTEGER NOT NULL DEFAULT 0
        CHECK (bootstrap IN (0, 1));

ALTER TABLE workspace_edit_journal
    ADD COLUMN configuration_source TEXT NOT NULL DEFAULT ''
        CHECK (configuration_source IN ('', 'explicit', 'conventional_yml', 'conventional_yaml'));
