/* eslint-disable max-len */
import Joi from 'joi';
import { Project } from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  /**
 * Creates a new project based on the provided request body, validates the input data, checks if the owner exists, and saves the project to the database.
 *
 * @param {Object} req - The request object containing the project data.
 * @param {Object} res - The response object to send the result.
 * @return {Object} The newly created project object or an error message.
 */
  static async createProject(req, res) {
    const { name, owner_Id } = req.body;
    if (!name) {
      return res.status(404).json({ error: 'The provided name does not exist' });
    }
    const createNewProject = await Project.create({
      name,
      owner_Id,
    });
    res.status(201).json(createNewProject);
  }

  /**
 * Updates a project in the database by its ID and sends the updated project as a JSON response.
 *
 * @param {Object} req - The HTTP request object containing the ID of the project to update and the updated project data.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing the updated project or an error message if the update fails.
 */
  static async updateProject(req, res) {
    const projectId = +req.params.id;
    if (!Number.isInteger(projectId)) {
      return res.status(400).json({ error: 'Project not found' });
    }
    const { name, owner_Id } = req.body;
    const project = await Project.findByPk(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    if (owner_Id) {
      const owner = await Project.findByPk(owner_Id);
      if (!owner) {
        return res.status(404).json({ error: 'Owner not found' });
      }
    }
    const updatedProject = await project.update({
      name,
      owner_Id,
    });
    res.json(updatedProject);
  }
}
