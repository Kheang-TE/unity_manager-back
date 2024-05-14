import { Model, DataTypes } from 'sequelize';
import sequelize from './sequelizeClient.js';

export default class Tag extends Model {}

Tag.init({
  name: {
    type: DataTypes.TEXT,
    allowNull: false,
    unique: true,
  },
  code_color: {
    type: DataTypes.STRING(7),
    allowNull: false,
    defaultValue: '#FFFFFF',
  },
}, {
  sequelize,
  tableName: 'tag',
});
