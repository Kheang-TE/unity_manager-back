-- Insert data into "user"
INSERT INTO "user" (email, password, firstname, lastname, code_color, created_at, updated_at)
VALUES
('john.doe@example.com', 'password123', 'John', 'Doe', '#a1b2c3', NOW(), NOW()),
('jane.smith@example.com', 'password123', 'Jane', 'Smith', '#b2c3d4', NOW(), NOW()),
('alice.jones@example.com', 'password123', 'Alice', 'Jones', '#c3d4e5', NOW(), NOW()),
('bob.brown@example.com', 'password123', 'Bob', 'Brown', '#d4e5f6', NOW(), NOW()),
('kheang@oclock.com', '$2b$10$PtUsimIZogwogiEfIlhXte7BIcgu.sCZ1AwiBJAIe3dcgQ4fp6zSW', 'Kheang', 'TE', '#d4e5f6', NOW(), NOW());

-- Insert data into "project"
INSERT INTO "project" (name, owner_id, created_at, updated_at)
VALUES
('Project Alpha', 1, NOW(), NOW()),
('Project Beta', 2, NOW(), NOW()),
('Project Gamma', 3, NOW(), NOW());

-- Insert data into "list"
INSERT INTO "list" (name, position, code_color, project_id, created_at, updated_at)
VALUES
('Todo', 1.0, '#ffddcc', 1, NOW(), NOW()),
('Done', 2.0, '#ddeeff', 1, NOW(), NOW()),
('In Progress', 1.5, '#ccffee', 2, NOW(), NOW()),
('Review', 2.5, '#eeddcc', 2, NOW(), NOW());

-- Insert data into "card"
INSERT INTO "card" (name, content, position, list_id, created_at, updated_at)
VALUES
('test1', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit', 1.0, 1, NOW(), NOW()),
('test2', 'Officia deserunt mollit anim id est laborum', 2.0, 1, NOW(), NOW()),
('test3', 'Ut enim ad minim veniam, quis nostrud exercitation', 1.0, 2, NOW(), NOW()),
('test4', 'Duis aute irure dolor in reprehenderit in voluptate', 2.0, 2, NOW(), NOW());

-- Insert data into "project_has_user"
INSERT INTO "project_has_user" (project_id, user_id, created_at, updated_at)
VALUES
(1, 5, NOW(), NOW()),
(1, 2, NOW(), NOW()),
(2, 5, NOW(), NOW()),
(2, 4, NOW(), NOW()),
(3, 5, NOW(), NOW()),
(3, 3, NOW(), NOW());

-- Insert data into "tag"
INSERT INTO "tag" (name, code_color, created_at, updated_at)
VALUES
('Urgent', '#ff1122', NOW(), NOW()),
('Optional', '#2211ff', NOW(), NOW()),
('Important', '#33cc33', NOW(), NOW()),
('Review', '#ffaa00', NOW(), NOW());

-- Insert data into "card_has_tag"
INSERT INTO "card_has_tag" (tag_id, card_id, created_at, updated_at)
VALUES
(1, 1, NOW(), NOW()),
(2, 2, NOW(), NOW()),
(3, 3, NOW(), NOW()),
(4, 4, NOW(), NOW());

-- Insert data into "card_has_user"
INSERT INTO "card_has_user" (user_id, card_id, created_at, updated_at)
VALUES
(1, 1, NOW(), NOW()),
(2, 2, NOW(), NOW()),
(3, 3, NOW(), NOW()),
(4, 4, NOW(), NOW());