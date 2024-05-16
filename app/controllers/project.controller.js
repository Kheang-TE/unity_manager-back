/* eslint-disable max-len */
import { Project } from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  static stringTableName = 'Project';
}
