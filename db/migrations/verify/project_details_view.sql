-- Verify unity_manager:project_details_view on pg

BEGIN;

SELECT 1
FROM information_schema.views
WHERE table_name = 'project_details';

ROLLBACK;
