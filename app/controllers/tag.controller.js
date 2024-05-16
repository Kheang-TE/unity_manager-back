// eslint-disable-next-line import/no-unresolved, import/extensions
import { Tag } from '../models/index.js';
import coreController from './core.controller.js';

export default class tagController extends coreController {
  static tableName = Tag;

  static stringTableName = 'Tag';

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
