// eslint-disable-next-line import/no-unresolved, import/extensions
import { List } from '../models/index.js';
import coreController from './core.controller.js';

export default class listController extends coreController {
  static tableName = List;

  static stringTableName = 'List';
}
