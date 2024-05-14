import { Model, DataTypes } from 'sequelize';
import sequelize from './sequelizeClient.js';

export default class User extends Model {}

User.init({
  lastname: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  firstname: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  email: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  password: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  color: {
    type: DataTypes.TEXT(7),
    allowNull: false,
    defaultValue: '#FFFFFF',
  },
}, {
  sequelize,
  tableName: 'user',
});
