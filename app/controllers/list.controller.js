// eslint-disable-next-line import/no-unresolved, import/extensions
import { List, Card, User } from '../models/index.js';
import coreController from './core.controller.js';

export default class listController extends coreController {
  static tableName = List;

  static stringTableName = 'List';

  /**
   * Retrieves all lists associated with a project by its ID.
   *
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @return {Promise<Object>} The JSON response containing the lists.
   */
  static async getByProjectId(req, res) {
    const { id } = req.params;
    const result = await List.findAll({
      where: { project_id: id },
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
          order: [['position', 'ASC']],
        }],
      }],
    });
    return res.json(result);
  }
}
