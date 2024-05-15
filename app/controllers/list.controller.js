// eslint-disable-next-line import/no-unresolved, import/extensions
import Joi from 'joi';
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
    if (!name || typeof name !== 'string') {
      res.status(400).json({
        error: "Missing body parameter or invalid format: 'name'.",
      });
      return;
    }
    const createListVerificationError = Joi.object({
      name: Joi.string().min(1),
      position: Joi.number().integer().greater(0),
      code_color: Joi.string().min(1),
      project_id: Joi.number().integer().greater(0),
    })
      .min(1)
      .message('The name or position field is not valid.');

    const { error } = createListVerificationError.validate(req.body);
    if (error) {
      res.status(400).json({ error: error.message });
      return;
    }
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
    const updateListSchema = Joi.object({
      name: Joi.string().min(1),
      position: Joi.number().greater(0),
      code_color: Joi.string().min(7),
      project_id: Joi.number().integer().greater(0),
    });

    const { error } = updateListSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.message });
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
