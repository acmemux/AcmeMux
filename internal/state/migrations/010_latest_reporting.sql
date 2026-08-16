ALTER TABLE operation_latest ADD COLUMN report_runtime_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_runtime_identity AS BLOB)) <= 64);

ALTER TABLE operation_latest ADD COLUMN report_runtime_manifest_id TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_runtime_manifest_id AS BLOB)) <= 128);

ALTER TABLE operation_latest ADD COLUMN report_configuration_path TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_configuration_path AS BLOB)) <= 4095);

ALTER TABLE operation_latest ADD COLUMN report_storage_path TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_storage_path AS BLOB)) <= 4095);

ALTER TABLE operation_requested_item ADD COLUMN report_account TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_account AS BLOB)) <= 64);

ALTER TABLE operation_requested_item ADD COLUMN report_ca TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_ca AS BLOB)) <= 255);

ALTER TABLE operation_requested_item ADD COLUMN report_challenge_kind TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_challenge_kind AS BLOB)) <= 32);

ALTER TABLE operation_requested_item ADD COLUMN report_challenge_mode TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(report_challenge_mode AS BLOB)) <= 64);
