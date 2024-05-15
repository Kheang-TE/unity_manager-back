/* eslint-disable import/extensions */
/* eslint-disable max-len */
import { List, Card } from '../models/index.js';
import coreController from './core.controller.js';

export default class cardController extends coreController {
  static tableName = Card;

  /**
   * Creates a new card in the database and sends it as a JSON response.
   * @async
   * @param {Object} req - The HTTP request object containing the card data.
   * @param {Object} res - The HTTP response object.
   * @returns {Promise<void>} A JSON object containing the newly created card or an error message if the creation fails.
   */
  static async createCard(req, res) {
    const { name, content, list_id, position } = req.body;

    const list = await List.findByPk(list_id);
    if (!list) {
      return res
        .status(404)
        .json({ error: "The provided list_id does not exist" });
    }

    const createdCard = await Card.create({
      name,
      content,
      list_id,
      position,
    });
    return res.status(201).json(createdCard);
  }

  /**
   * Updates a card in the database by its ID and sends the updated card as a JSON response.
   * @async
   * @param {Object} req - The HTTP request object containing the ID of the card to update and the updated card data.
   * @param {Object} res - The HTTP response object.
   * @returns {Promise<void>} A JSON object containing the updated card or an error message if the update fails.
   */
  static async updateCard(req, res) {
    const cardId = +req.params.id;

    if (!Number.isInteger(cardId)) {
      return res.status(404).json({ error: 'Provided ID should be an integer' });
    }

    const card = await Card.findByPk(cardId);

    if (!card) {
      return res.status(404).json({ error: "Card not found" });
    }
    const {
      name, content, position, list_id,
    } = req.body;

    if (list_id) {
      const list = await List.findByPk(list_id);
      if (!list) {
        return res.status(404).json({ error: "List not found" });
      }
    }

    const updatedCard = await card.update({
      name,
      content,
      position,
      list_id,
    });

    return res.json(updatedCard);
  }
}
