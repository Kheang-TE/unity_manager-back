import { Model, DataTypes } from 'sequelize';
import sequelize from './sequelizeClient.js';

export default class Card extends Model {}

Card.init({
  name: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  position: {
    type: DataTypes.FLOAT,
    allowNull: false,
  },
  list_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    onDelete: 'CASCADE',
  },
}, {
  sequelize,
  tableName: 'card',
});
