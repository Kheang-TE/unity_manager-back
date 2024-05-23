/* eslint-disable max-len */
import {
  Project, User, List, Card, Tag,
} from '../models/index.js';
import coreController from './core.controller.js';

export default class projectController extends coreController {
  static tableName = Project;

  static stringTableName = 'Project';

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
            include: [{
              model: Card, // Les cartes des listes
              attributes: ['id', 'name', 'content', 'position'],
              as: 'cards',
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
        include: [{
          model: Card, // Les cartes des listes
          attributes: ['id', 'name', 'content', 'position'],
          as: 'cards',
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
      }],

    });
    res.json(project);
  }

  static async getProjectByUser(req, res) {
    const userId = +req.user.id;
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
    res.json(project);
  }
}
