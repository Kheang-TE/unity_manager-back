/* eslint-disable max-len */
import ApiError from '../errors/api.error.js';
import {
  Project, User, List, Card, Tag, Message,
} from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  static stringTableName = 'Project';

  /**
   * Creates a new project with the given input data and adds the owner to the project.
   *
   * @param {Object} req - The request object containing the project data.
   * @param {Object} res - The response object to send the result.
   * @returns {Promise<Object>} The created project as a JSON response with status code 201.
   * @throws {ApiError} If the owner is not found.
   */
  static async create(req, res, next) {
    const input = req.body;

    const project = await this.tableName.create({ name: input.name, owner_id: input.owner_id });
    // find the owner
    const owner = await User.findByPk(input.owner_id);
    if (!owner) {
      next(new ApiError(404, 'Owner not found', 'Owner not found'));
    }
    // add the owner to the project
    await project.addCollaborator(owner);

    return res.status(201).json(project);
  }

  /**
 * Retrieves the details of a user, including their projects, collaborators, lists, cards, users, and tags.
 *
 * @param {Object} req - The request object containing the user ID in the params.
 * @param {Object} res - The response object to send the user details.
 * @return {Promise<Object>} The user details as a JSON response.
 */
  static async getUserDetails(req, res) {
    const { id } = req.params;
    const project = await User.findByPk(id, {
      include: [{
        model: Project,
        as: 'projects',
        through: { attributes: [] },
        include: [
          {
            model: User, // Les collaborateurs des projets
            attributes: ['id', 'firstname', 'lastname'],
            as: 'collaborators',
            through: { attributes: [] },
          },
          {
            model: List, // Les listes du projet
            attributes: ['id', 'name', 'position', 'code_color'],
            as: 'lists',
            order: [['position', 'ASC']],
            include: [{
              model: Card, // Les cartes des listes
              attributes: ['id', 'name', 'content', 'position'],
              as: 'cards',
              order: [['position', 'ASC']],
              include: [{
                model: User, // L'utilisateur associé à chaque carte
                attributes: ['firstname', 'lastname'],
                through: { attributes: [] },
                as: 'users',
              },
              {
                model: Tag, // Les tags des cartes
                attributes: ['id', 'name', 'code_color'],
                through: { attributes: [] },
                as: 'tags',
              }],
            }],
          },
        ],
      }],
    });
    res.send(project);
  }

  /**
   * Retrieves a project with its details, including collaborators, lists, cards, users, and tags.
   *
   * @param {Object} req - The request object containing the project ID in the params.
   * @param {Object} res - The response object to send the project details.
   * @return {Promise<Object>} The project details as a JSON response.
   */
  static async getProjectWithDetails(req, res) {
    const { id } = req.params;
    const project = await Project.findByPk(id, {
      include: [{
        model: User, // The collaborators of the project
        attributes: ['id', 'firstname', 'lastname'],
        as: 'collaborators',
        through: { attributes: [] },
      },
      {
        model: List, // The lists of the project
        attributes: ['id', 'name', 'position', 'code_color'],
        as: 'lists',
        separate: true,
        order: [['position', 'ASC']],
        include: [{
          model: Card, // The cards of the list
          attributes: ['id', 'name', 'content', 'list_id', 'position'],
          as: 'cards',
          separate: true,
          order: [['position', 'ASC']],
          include: [{
            model: User, // The users of the card
            attributes: ['firstname', 'lastname'],
            through: { attributes: [] },
            order: [['position', 'ASC']],
            as: 'users',
          },
          {
            model: Tag, // The tags of the card
            attributes: ['id', 'name', 'code_color'],
            through: { attributes: [] },
            as: 'tags',
          }],
        }],
      }],
    });
    const messages = await Message.find({ project_id: id });
    project.dataValues.messages = messages;
    res.json(project);
  }

  /**
   * Retrieves all projects associated with the given user ID.
   *
   * @param {Object} req - The request object containing the user ID.
   * @param {Object} res - The response object to send the result.
   * @param {Function} next - The next middleware function.
   * @return {Promise<Object>} The project data as a JSON response.
   * @throws {ApiError} If no project is found for the user ID.
   */
  static async getProjectByUser(req, res, next) {
    const userId = req.user.id;
    const project = await Project.findAll({
      include: [{
        model: User, // The collaborators of the project
        attributes: ['id'],
        as: 'collaborators',
        through: { attributes: [] },
        where: {
          id: userId,
        },
      }],
    });

    if (project.length === 0) {
      return next(new ApiError(404, 'No project found', 'No project found'));
    }

    // Search for messages
    const messages = await Message.find({ project_id: project[0].id });
    // Add the messages to the project object
    project.message = messages;

    return res.json(project);
  }
}
