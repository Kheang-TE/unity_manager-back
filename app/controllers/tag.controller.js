// eslint-disable-next-line import/no-unresolved, import/extensions
import { Tag } from '../models/index.js';
import coreController from './core.controller.js';

export default class tagController extends coreController {
  static tableName = Tag;

  /**
   * Create a new tag based on the provided name.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The newly created tag or an error message
   */
  static async createTag(req, res) {
    const { name } = req.body;
    if (!name || typeof name !== 'string') {
      return res.status(400).json({
        error: "Missing body parameter or invalid format: 'name'.",
      });
    }

    const newTag = await Tag.create({ name });
    return res.status(200).json(newTag);
  }

  /**
   * Updates a tag based on the provided request body.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The updated tag object or an error message
   */
  static async updateTag(req, res) {
    const { body } = req;
    if (!body.name || !body.code_color) {
      return res.status(404).json({
        error: 'The requested resource could not be found on the server.',
      });
    }
    const tagId = +req.params.id;
    if (!Number.isInteger(tagId)) {
      return res.status(404).json({ error: 'The ID of tag is not defined. ' });
    }

    const updateOneTag = await Tag.findByPk(tagId);
    await updateOneTag.update(body);
    await updateOneTag.save();
    return res.status(200).json(updateOneTag);
  }

  /**
   * Retrieves a tag associated with a card based on the provided card and tag IDs.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The found tag object or an error message
   */
  static async getTagWithCard(req, res) {
    const cardId = +req.params.card_id;
    const tagId = +req.params.tag_id;
    try {
      const findTag = await Tag.findOne({ card_id: cardId, tag_id: tagId });
      if (!findTag) {
        return res.status(404).json({
          error: 'The requested resource could not be found on the server.',
        });
      }
      return res.json(findTag);
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'Unexpected server error' });
    }
  }

  /**
   * Deletes a tag associated with a card based on the provided card and tag IDs.
   *
   * @param {Object} req - The request object
   * @param {Object} res - The response object
   * @return {Object} The deleted tag object or an error message
   */
  static async deleteAssociatTagCard(req, res) {
    try {
      const cardId = +req.params.card_id;
      const tagId = +req.params.tag_id;

      const findTag = await Tag.findOneAndDelete({ card_id: cardId, tag_id: tagId });

      if (!findTag) {
        return res.status(404).json({ error: 'The association between the card and tag could not be found.' });
      }

      return res.json({ message: 'Association between card and tag was successfully deleted.' });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'An unexpected server error occurred' });
    }
  }
}
