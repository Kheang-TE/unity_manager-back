/* eslint-disable import/extensions */
/* eslint-disable max-len */
import { List, Card } from '../models/index.js';
import coreController from './core.controller.js';

export default class cardController extends coreController {
  static tableName = Card;

  static stringTableName = 'Card';
}
