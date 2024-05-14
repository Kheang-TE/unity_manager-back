-- Revert unity_manager:project_details_view from pg

BEGIN;

DROP VIEW IF EXISTS project_details;

COMMIT;
