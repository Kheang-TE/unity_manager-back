/* eslint-disable max-len */
// eslint-disable-next-line import/no-unresolved, import/extensions
import Joi from "joi";
import { List, Card } from '../models/index.js';

/**
 * Retrieves all cards from the database and sends them as a JSON response.
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing all available cards or an error message if no cards are found.
 */

export async function getAllCards(req, res) {
  const cards = await Card.findAll();
  if (!cards) {
    return res.status(404).json({ error: 'Cards not found' });
  }
  return res.json(cards);
}

/**
 * Retrieves a single card from the database by its ID and sends it as a JSON response.
 * @async
 * @param {Object} req - The HTTP request object containing the ID of the card to retrieve.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing the retrieved card or an error message if the card is not found.
 */
export async function getOneCard(req, res) {
  const { error } = Joi.number().integer().greater(0).validate(req.params.id);
  if (error) {
    return res.status(404).json({ error: `Card not found. Verify the provided ID. ${error.message}` });
  }
  const cardId = +req.params.id;

  const card = await Card.findByPk(cardId);

  if (!card) {
    return res.status(404).json({ error: 'Card not found.' });
  }

  return res.json(card);
}

/**
 * Creates a new card in the database and sends it as a JSON response.
 * @async
 * @param {Object} req - The HTTP request object containing the card data.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing the newly created card or an error message if the creation fails.
 */
export async function createCard(req, res) {
  const createCardSchema = Joi.object({
    name: Joi.string().min(1).required(),
    content: Joi.string().min(1).required(),
    list_id: Joi.number().integer().greater(0).required(),
    position: Joi.number().greater(0),
  });

  const { error } = createCardSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }

  const {
    content, list_id, position, color,
  } = req.body;

  const list = await List.findByPk(list_id);
  if (!list) {
    return res.status(404).json({ error: 'The provided list_id does not exist' });
  }

  const createdCard = await Card.create({
    content,
    list_id,
    position,
    color,
  });
  return res.status(201).json(createdCard);
}

/**
 * Deletes a card from the database by its ID.
 * @async
 * @param {Object} req - The HTTP request object containing the ID of the card to delete.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A 204 No Content response if the deletion is successful, or an error message if the card is not found.
 */
export async function deleteCard(req, res) {
  const cardId = +req.params.id;
  if (!Number.isInteger(cardId)) {
    return res.status(404).json({ error: 'Card not found' });
  }
  const card = await Card.findByPk(cardId);
  if (!card) {
    return res.status(404).json({ error: 'Card not found' });
  }
  await card.destroy();
  return res.status(204).end();
}

/**
 * Updates a card in the database by its ID and sends the updated card as a JSON response.
 * @async
 * @param {Object} req - The HTTP request object containing the ID of the card to update and the updated card data.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing the updated card or an error message if the update fails.
 */
export async function updateCard(req, res) {
  const cardId = +req.params.id;
  if (!Number.isInteger(cardId)) {
    return res.status(404).json({ error: 'Card not found' });
  }
  const updateCardSchema = Joi.object({
    name: Joi.string().min(1),
    content: Joi.string().min(1),
    position: Joi.number().integer().greater(0),
    list_id: Joi.number().integer().greater(0),
  }).min(1).message("Missing body parameters. Provide at least 'content' or 'position' or 'list_id' or 'color' properties");

  const { error } = updateCardSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }

  const {
    name, content, position, list_id,
  } = req.body;

  const card = await Card.findByPk(cardId);

  if (!card) {
    return res.status(404).json({ error: 'Card not found' });
  }

  if (list_id) {
    const list = await List.findByPk(list_id);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
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
