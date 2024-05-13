-- Insert data into "user"
INSERT INTO "user" (email, password, firstname, lastname, code_color, created_at, updated_at)
VALUES
('john.doe@example.com', 'password123', 'John', 'Doe', '#a1b2c3', NOW(), NOW()),
('jane.smith@example.com', 'password123', 'Jane', 'Smith', '#b2c3d4', NOW(), NOW());

-- Insert data into "project"
INSERT INTO "project" (name, owner_id, created_at, updated_at)
VALUES
('Project Alpha', 1, NOW(), NOW()),
('Project Beta', 2, NOW(), NOW());

-- Insert data into "list"
INSERT INTO "list" (name, position, code_color, project_id, created_at, updated_at)
VALUES
('Todo', 1.0, '#ffddcc', 1, NOW(), NOW()),
('Done', 2.0, '#ddeeff', 1, NOW(), NOW());

-- Insert data into "card"
INSERT INTO "card" (name,content,position, list_id, created_at, updated_at)
VALUES
('test1','Lorem ipsum dolor sit amet, consectetur adipiscing elit',1.0, 1, NOW(), NOW()),
('test2','Officia deserunt mollit anim id est laborum',2.0, 1, NOW(), NOW());

-- Insert data into "project_has_user"
INSERT INTO "project_has_user" (project_id, user_id, created_at, updated_at)
VALUES
(1, 1, NOW(), NOW()),
(1, 2, NOW(), NOW());

-- Insert data into "tag"
INSERT INTO "tag" (name, code_color, created_at, updated_at)
VALUES
('Urgent', '#ff1122', NOW(), NOW()),
('Optional', '#2211ff', NOW(), NOW());

-- Insert data into "card_has_tag"
INSERT INTO "card_has_tag" (tag_id, card_id, created_at, updated_at)
VALUES
(1, 1, NOW(), NOW()),
(2, 2, NOW(), NOW());

-- Insert data into "card_has_user"
INSERT INTO "card_has_user" (user_id, card_id, created_at, updated_at)
VALUES
(1, 1, NOW(), NOW()),
(2, 2, NOW(), NOW());