-- Deploy unity_manager:project_details_view to pg

BEGIN;

CREATE OR REPLACE VIEW project_details AS
SELECT 
    p.id AS project_id,
    p.name AS project_name,
    (
        SELECT json_agg(l)
        FROM (
            SELECT l.*,
                (
                    SELECT json_agg(c)
                    FROM (
                        SELECT c.*,
                            (
                                SELECT json_agg(u1)
                                FROM (
                                    SELECT u1.*
                                    FROM "user" u1
                                    JOIN card_has_user chu ON u1.id = chu.user_id
                                    WHERE chu.card_id = c.id
                                ) u1
                            ) AS card_owners
                        FROM card c
                        WHERE c.list_id = l.id
                    ) c
                ) AS cards
            FROM list l
            WHERE l.project_id = p.id
        ) l
    ) AS lists,
    (
        SELECT json_agg(t)
        FROM (
            SELECT DISTINCT t.*
            FROM tag t
            JOIN card_has_tag cht ON t.id = cht.tag_id
            JOIN card c ON cht.card_id = c.id
            JOIN list l ON c.list_id = l.id
            WHERE l.project_id = p.id
        ) t
    ) AS tags,
    (
        SELECT json_agg(u2)
        FROM (
            SELECT DISTINCT u2.*
            FROM "user" u2
            JOIN project_has_user pu ON u2.id = pu.user_id
            WHERE pu.project_id = p.id
        ) u2
    ) AS project_users
FROM
    Project p
GROUP BY p.id, p.name;

COMMIT;
