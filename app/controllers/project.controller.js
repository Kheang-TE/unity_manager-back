/* eslint-disable max-len */
import { Project } from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  static stringTableName = 'Project';

  static async getOne(req, res) {
    console.log('req.params', req.params);
    const { id } = req.params;
    const project = await Project.findByPk(id);
    res.send(project);
  }
}
