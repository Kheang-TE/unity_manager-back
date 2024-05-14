import { Router } from 'express';
import * as cardController from '../controllers/card.controller.js';
import cw from './controlerWrapper.router.js';

const router = Router();
export default router;

/**
 * Retrieves all cards.
 * @route GET /cards
 * @group Cards - Operations on cards
 * @returns {Array<Object>} List of cards.
 */
router.get('/cards', cw(cardController.getAllCards));

/**
 * Retrieves a specific card by its ID.
 * @route GET /cards/{id}
 * @group Cards - Operations on cards
 * @param {string} req.params.id - The unique identifier of the card to retrieve.
 * @returns {Object} The requested card.
 */
router.get('/cards/:id', cw(cardController.getOneCard));

/**
 * Creates a new card.
 * @route POST /cards
 * @group Cards - Operations on cards
 * @param {Object} req.body - Card data to create.
 * @returns {Object} The created card.
 */
router.post('/cards', cw(cardController.createCard));

/**
 * Updates an existing card.
 * @route PATCH /cards/{id}
 * @group Cards - Operations on cards
 * @param {string} req.params.id - The unique identifier of the card to update.
 * @param {Object} req.body - Updated card data.
 * @returns {Object} The updated card.
 */
router.patch('/cards/:id', cw(cardController.updateCard));

/**
 * Deletes an existing card.
 * @route DELETE /cards/{id}
 * @group Cards - Operations on cards
 * @param {string} req.params.id - The unique identifier of the card to delete.
 * @returns {string} Deletion confirmation message.
 */
router.delete('/cards/:id', cw(cardController.deleteCard));
