// eslint-disable-next-line import/no-unresolved, import/extensions
import { List } from '../models/index.js';
import coreController from './core.controller.js';

export default class listController extends coreController {
  static tableName = List;

  /**
     * Create a new list with the provided name and position.
     *
     * @param {Object} req - The request object
     * @param {Object} res - The response object
     * @return {Object} The newly created list or an error message
     */
  static async createList(req, res) {
    const {
      name, position, code_color, project_id,
    } = req.body;
    const newList = await List.create({
      name, position, code_color, project_id,
    });
    res.status(201).json(newList);
  }

  // eslint-disable-next-line consistent-return
  /**
     * Updates a list based on the provided request body.
     *
     * @param {Object} req - The request object
     * @param {Object} res - The response object
     * @return {Object} The updated list object or an error message
     */
  static async updateList(req, res) {
    const {
      name, position, code_color, project_id,
    } = req.body;
    if (!name || !position) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }
    const listId = +req.params.id;
    if (!Number.isInteger(listId)) {
      return res.status(404).json({ error: 'The ID of list is not defined. ' });
    }

    const updateOneList = await List.findByPk(+listId);
    if (!updateOneList) {
      return res.status(404).json({ error: 'List not found.' });
    }
    if (name) {
      updateOneList.name = name;
    }
    if (position) {
      updateOneList.position = position;
    }
    if (code_color) {
      updateOneList.code_color = code_color;
    } if (position) {
      updateOneList.project_id = project_id;
    }
    await updateOneList.save();
    res.status(200).json(updateOneList);
  }
}
