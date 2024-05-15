import { Model, DataTypes } from 'sequelize';
import sequelize from './sequelizeClient.js';

export default class List extends Model {}

List.init({
  name: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  position: {
    type: DataTypes.FLOAT,
    allowNull: false,
  },
  code_color: {
    type: DataTypes.TEXT(7), // Hexadecimal code #FF00FF
    allowNull: false,
    defaultValue: '#FFFFFF', // White
  },

}, {
  sequelize, // Instance Sequelize
  tableName: 'list',
});
