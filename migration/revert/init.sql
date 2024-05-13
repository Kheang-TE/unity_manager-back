-- Revert unity_manager:init from pg

BEGIN;

DROP TABLE 
"card_has_user",
"card_has_tag",
"tag",
"project_has_user",
"card",
"list",
"project",
"user";

DROP DOMAIN "hexColor";

COMMIT;
