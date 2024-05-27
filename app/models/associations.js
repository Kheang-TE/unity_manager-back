// Importer nos modèles
import Card from './Card.js';
import List from './List.js';
import Tag from './Tag.js';
import Project from './Project.js';
import User from './User.js';
import sequelize from './sequelizeClient.js';

// List <--> Card (One-to-Many)
List.hasMany(Card, {
  as: 'cards', // When I request a list, I want to get its cards
  foreignKey: {
    name: 'list_id',
    allowNull: false,
  },
  onDelete: 'CASCADE', // When I delete a list, I want to delete its cards
});
Card.belongsTo(List, {
  as: 'list', // When I request a card, I want to get its list
  foreignKey: 'list_id',
});

// Project <--> List (One-to-Many)
Project.hasMany(List, {
  as: 'lists',
  foreignKey: {
    name: 'project_id',
    allowNull: false,
  },
  onDelete: 'CASCADE',
});

// Card <--> Tag (Many-to-Many)
Card.belongsToMany(Tag, {
  as: 'tags',
  through: 'card_has_tag',
  foreignKey: 'card_id',
});

Tag.belongsToMany(Card, {
  as: 'cards',
  through: 'card_has_tag',
  foreignKey: 'tag_id',
});

// Card <--> User (Many-to-Many)
Card.belongsToMany(User, {
  as: 'users',
  through: 'card_has_user',
  foreignKey: 'card_id',
});

User.belongsToMany(Card, {
  as: 'cards',
  through: 'card_has_user',
  foreignKey: 'user_id',
});

// Project <--> User(One-to-Many)
Project.belongsTo(User, {
  as: 'owner',
  foreignKey: {
    name: 'owner_id',
    allowNull: false,
  },
  onDelete: 'CASCADE',
});

User.hasMany(Project, {
  as: 'ownedProjects',
  foreignKey: 'owner_id',
});

// Project <--> User (Many-to-Many)
Project.belongsToMany(User, {
  as: 'collaborators',
  through: 'project_has_user',
  foreignKey: 'project_id',
});

User.belongsToMany(Project, {
  as: 'projects',
  through: 'project_has_user',
  foreignKey: 'user_id',
});

export {
  Card, List, Tag, Project, User, sequelize,
};
