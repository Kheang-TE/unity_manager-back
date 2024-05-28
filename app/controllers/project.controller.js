/* eslint-disable max-len */
import {
  Project, User, List, Card, Tag, Message,
} from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  static stringTableName = 'Project';

  static async create(req, res) {
    const input = req.body;

    const project = await this.tableName.create({ name: input.name, owner_id: input.owner_id });
    // find the owner
    const owner = await User.findByPk(input.owner_id);
    if (!owner) {
      throw new ApiError(404, 'Owner not found', 'Owner not found');
    }
    // add the owner to the project
    await project.addCollaborator(owner);

    return res.status(201).json(project);
  }

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

  static async getProjectWithDetails(req, res) {
    const { id } = req.params;
    const project = await Project.findByPk(id, {
      include: [{
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
          attributes: ['id', 'name', 'content', 'list_id', 'position'],
          as: 'cards',
          include: [{
            model: User, // L'utilisateur associé à chaque carte
            attributes: ['firstname', 'lastname'],
            through: { attributes: [] },
            order: [['position', 'ASC']],
            as: 'users',
          },
          {
            model: Tag, // Les tags des cartes
            attributes: ['id', 'name', 'code_color'],
            through: { attributes: [] },
            as: 'tags',
          }],
        }],
      }],

    });
    const messages = await Message.find({ project_id: id });
    project.dataValues.messages = messages;
    res.send(project);
  }

  static async getProjectByUser(req, res) {
    const userId = req.user.id;
    const project = await Project.findAll({
      include: [{
        model: User, // Les collaborateurs des projets
        attributes: ['id'],
        as: 'collaborators',
        through: { attributes: [] },
        where: {
          id: userId,
        },
      }],
    });

    if (project.length === 0) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }

    // Search for messages
    const messages = await Message.find({ project_id: project[0].id });

    project.message = messages;
    return res.json(project);
  }
}
