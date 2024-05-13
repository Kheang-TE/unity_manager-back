-- Revert unity_manager:init from pg

BEGIN;

DROP TABLE "card","list","project","user","project_has_user","tag","card_has_tag","card_has_user";

DROP DOMAIN "HexColor";

COMMIT;
