-- Verify unity_manager:init on pg

BEGIN;

SELECT id FROM "card" WHERE false;

SELECT id FROM "list" WHERE false;

SELECT id FROM "project" WHERE false;

SELECT id FROM "user" WHERE false;

SELECT id FROM "project_has_user" WHERE false;

SELECT id FROM "tag" WHERE false;

SELECT id FROM "card_has_tag" WHERE false;

SELECT id FROM "card_has_user" WHERE false;

ROLLBACK;
