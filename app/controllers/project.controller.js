/* eslint-disable max-len */
import ApiError from '../errors/api.error.js';
import {
  Project, User, List, Card, Tag, Message, sequelize,
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
      },
      {
        model: Tag, // The tags of the card
        attributes: ['id', 'name', 'code_color'],
        as: 'tags',
        separate: true,
        order: [['name', 'ASC']],
      }],
    });
    const messages = await Message.find({ project_id: id });
    const messagesWithUser = await Promise.all(messages.map(async (message) => {
      try {
        const user = await User.findByPk(message.user_id);
        return { ...message.toJSON(), user: user ? { firstname: user.firstname, lastname: user.lastname, color: user.code_color } : null };
      } catch (error) {
        console.error('Error while getting user:', error);
        return { ...message.toJSON(), user: null };
      }
    }));
    project.dataValues.messages = messagesWithUser;
    res.send(project);
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
      order: [['name', 'ASC']],
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
      // the user has no project
      return res.status(200).json([]);
    }

    // Search for messages
    const messages = await Message.find({ project_id: project[0].id });
    // Add the messages to the project object
    project.message = messages;

    return res.json(project);
  }

  static async createCollaborators(req, res) {
    console.log('im here', req.body);
    const { id } = req.params;
    const collaboratorEmail = req.body.email;
    const project = await Project.findByPk(id);
    const collaborator = await User.findOne({ where: { email: collaboratorEmail } });
    await project.addCollaborator(collaborator);

    return res.send(collaborator);
  }

  static async getLastCollaborator(req, res) {
    const { id } = req.params;
    const project = await Project.findByPk(id);
    const collaborator = await project.getCollaborators({
      attributes: ['id', 'firstname', 'lastname', 'code_color'], // Sélectionnez les attributs que vous souhaitez récupérer des collaborateurs
      order: [[sequelize.col('project_has_user.created_at'), 'DESC']], // Utilisez sequelize.col pour référencer la colonne correctement
      limit: 1, // Récupère uniquement le collaborateur le plus récemment ajouté
    });
    return res.send(collaborator[0]);
  }

  static async deleteOne(req, res, next) {
    const id = +req.params.id;
    if (!Number.isInteger(id)) {
      next(new ApiError(400, 'Bad Request', 'The provided ID is not a number'));
    }
    const result = await Project.findByPk(id);
    if (!result) {
      next(new ApiError(404, 'Data not found', `${this.stringTableName} not found with the provided the ID: ${id}`));
    }
    await result.destroy();
    return res.status(204).end();
  }
}
