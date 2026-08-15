DELETE FROM runtime_selection;

ALTER TABLE runtime_selection ADD COLUMN capabilities TEXT NOT NULL DEFAULT ''
    CHECK (capabilities IN ('', 'cap_net_bind_service=ep'));

ALTER TABLE runtime_selection ADD COLUMN build_provenance_complete INTEGER NOT NULL DEFAULT 0
    CHECK (build_provenance_complete IN (0, 1));

ALTER TABLE runtime_selection ADD COLUMN build_command_path TEXT NOT NULL DEFAULT ''
    CHECK (length(build_command_path) <= 256);

ALTER TABLE runtime_selection ADD COLUMN build_dependency_graph_sha256 TEXT NOT NULL DEFAULT ''
    CHECK (
        length(build_dependency_graph_sha256) IN (0, 64)
        AND build_dependency_graph_sha256 NOT GLOB '*[^0-9a-f]*'
    );
